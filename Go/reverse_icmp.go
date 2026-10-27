package pingtunnel

// Reverse ICMP is a transport for the existing authenticated v4 session.
// The foreign VPS owns ICMP Echo Requests; Iran emits user data ONLY as a
// reply to a fresh, MAC-authenticated request from the configured peer.
import (
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "errors"
 "io"
 "sync"
 "time"

 "golang.org/x/crypto/hkdf"
)

var reverseMagic = [4]byte{'P','T','R','4'}
const (
 reversePoll byte = 1
 reverseAck byte = 2
 reverseData byte = 3
 reverseHeaderSize = 23
 reverseMACSize = 16
 reverseMaxFrames = 2048
 reverseMaxBytes = 4 * 1024 * 1024
 reverseFrameTTL = 12 * time.Second
)
type reverseFrame struct {
 payload []byte
 since time.Time
}
type reverseICMP struct {
 mu sync.Mutex
 region string
 macKey [32]byte
 boot uint64
 nextSeq uint64
 seenBoot uint64
 pollSeen secureReplay
 replySeen secureReplay
 active bool
 lastPoll time.Time
 lastReply time.Time
 started time.Time
 frames []reverseFrame
 frameBytes int
 dropped uint64
 demand bool
 hinted int
 hotUntil time.Time
}
func newReverseICMP(region string, root []byte)(*reverseICMP,error) {
 r:=&reverseICMP{region:region,started:time.Now()}
 if _,err:=io.ReadFull(hkdf.New(sha256.New,root,nil,[]byte("pingtunnel-v4/reverse-icmp-poll")),r.macKey[:]);err!=nil{return nil,err}
 var boot [8]byte
 if _,err:=rand.Read(boot[:]);err!=nil{return nil,err}
 r.boot=binary.BigEndian.Uint64(boot[:])
 if r.boot==0{r.boot=1}
 return r,nil
}
func (r *reverseICMP) sign(body []byte)[]byte {
 mac:=hmac.New(sha256.New,r.macKey[:])
 _,_=mac.Write(body)
 return mac.Sum(nil)[:reverseMACSize]
}
// All poll/reply metadata is PSK authenticated, domain separated from the
// X25519 key agreement. Replay windows reject repeated polling credits.
func (r *reverseICMP) encode(op byte,boot,seq uint64,flags uint16,payload []byte)[]byte {
 b:=make([]byte,reverseHeaderSize,reverseHeaderSize+len(payload)+reverseMACSize)
 copy(b[:4],reverseMagic[:]);b[4]=op
 binary.BigEndian.PutUint64(b[5:13],boot)
 binary.BigEndian.PutUint64(b[13:21],seq)
 binary.BigEndian.PutUint16(b[21:23],flags)
 b=append(b,payload...)
 return append(b,r.sign(b)...)
}
func (r *reverseICMP) decode(b []byte)(byte,uint64,uint64,uint16,[]byte,bool){
 if len(b)<reverseHeaderSize+reverseMACSize || string(b[:4])!=string(reverseMagic[:]){return 0,0,0,0,nil,false}
 body:=b[:len(b)-reverseMACSize]
 if !hmac.Equal(r.sign(body),b[len(body):]){return 0,0,0,0,nil,false}
 return b[4],binary.BigEndian.Uint64(b[5:13]),binary.BigEndian.Uint64(b[13:21]),
  binary.BigEndian.Uint16(b[21:23]),body[reverseHeaderSize:],true
}
func (r *reverseICMP) isActive()bool {
 r.mu.Lock();defer r.mu.Unlock()
 return r.active
}
func (r *reverseICMP) activate(){
 r.mu.Lock();r.active=true;r.mu.Unlock()
}
func (r *reverseICMP) setDemand(demand bool){
 r.mu.Lock();r.demand=demand;r.mu.Unlock()
}
func (r *reverseICMP) makePoll()[]byte {
 r.mu.Lock()
 r.nextSeq++
 if r.nextSeq==0 {r.nextSeq=1}
 boot,seq:=r.boot,r.nextSeq
 r.mu.Unlock()
 return r.encode(reversePoll,boot,seq,0,nil)
}
// Returns the poll ticket and whether reverse transport is selected. Only a
// fresh ticket can drain one queued Iran-to-foreign data frame.
func (r *reverseICMP) acceptPoll(b []byte,ready bool,lastValid,timeNow time.Time)(uint64,uint64,bool,bool){
 if r.region!="iran"{return 0,0,false,false}
 op,boot,seq,_,payload,ok:=r.decode(b)
 if !ok||op!=reversePoll||len(payload)!=0||seq==0{return 0,0,false,false}
 r.mu.Lock()
 defer r.mu.Unlock()
 if boot!=r.seenBoot {
  // A new process may restart the poll counter. Do not allow a captured old
  // boot identifier to replace a peer that is actively polling.
  if r.seenBoot!=0 && timeNow.Sub(r.lastPoll)<2*time.Second{return 0,0,false,false}
  r.seenBoot=boot
  r.pollSeen=secureReplay{}
 }
 if !r.pollSeen.accept(seq){return 0,0,false,false}
 r.lastPoll=timeNow
 if !ready || (r.demand && (lastValid.IsZero()||timeNow.Sub(lastValid)>25*time.Second)){
  r.active=true
 }
 return boot,seq,r.active,true
}
func (r *reverseICMP) queueFrame(frame []byte)bool{
 r.mu.Lock();defer r.mu.Unlock()
 if r.region!="iran"||!r.active{return false}
 if len(frame)==0||len(frame)>10240 {r.dropped++;return true}
 for len(r.frames)>0 && (len(r.frames)>=reverseMaxFrames||r.frameBytes+len(frame)>reverseMaxBytes){
  r.frameBytes-=len(r.frames[0].payload)
  r.frames[0]=reverseFrame{}
  r.frames=r.frames[1:]
  r.dropped++
 }
 r.frames=append(r.frames,reverseFrame{payload:append([]byte(nil),frame...),since:time.Now()})
 r.frameBytes+=len(frame)
 return true
}
func (r *reverseICMP) popFrame(now time.Time)([]byte,int){
 r.mu.Lock();defer r.mu.Unlock()
 for len(r.frames)>0{
  first:=r.frames[0]
  r.frameBytes-=len(first.payload)
  r.frames[0]=reverseFrame{}
  r.frames=r.frames[1:]
  if now.Sub(first.since)>reverseFrameTTL{r.dropped++;continue}
  return first.payload,len(r.frames)
 }
 return nil,0
}
func (r *reverseICMP) reply(boot,seq uint64,payload []byte,backlog int,selected bool)[]byte {
 var flags uint16
 if selected {flags|=0x8000}
 if backlog>0x7fff{backlog=0x7fff}
 flags|=uint16(backlog)
 if len(payload)==0{return r.encode(reverseAck,boot,seq,flags,nil)}
 return r.encode(reverseData,boot,seq,flags,payload)
}
// Foreign: acknowledge each ticket once; duplicate kernel-generated Echo
// Replies containing our original request cannot be mistaken for responses.
func (r *reverseICMP) acceptReply(b []byte,now time.Time)([]byte,bool){
 if r.region!="foreign"{return nil,false}
 op,boot,seq,flags,payload,ok:=r.decode(b)
 if !ok||(op!=reverseAck && op!=reverseData){return nil,false}
 if op==reverseAck && len(payload)!=0{return nil,false}
 r.mu.Lock()
 defer r.mu.Unlock()
 if boot!=r.boot||seq==0||seq>r.nextSeq||r.nextSeq-seq>4096||!r.replySeen.accept(seq){return nil,false}
 r.lastReply=now
 if flags&0x8000!=0{r.active=true}
 r.hinted=int(flags&0x7fff)
 if len(payload)>0{r.hotUntil=now.Add(3*time.Second)}
 return payload,true
}
func (r *reverseICMP) pollInterval(ready bool,flows int,now time.Time)time.Duration {
 r.mu.Lock();defer r.mu.Unlock()
 if !ready{return 100*time.Millisecond}
 if !r.active{return 12*time.Second}
 if r.hinted>0||now.Before(r.hotUntil){return 3*time.Millisecond}
 if flows>0{return 10*time.Millisecond}
 return 250*time.Millisecond
}
func (r *reverseICMP) shouldProbe(ready bool,now time.Time)bool{
 r.mu.Lock();defer r.mu.Unlock()
 return r.region=="foreign" && (!ready||r.active||now.Sub(r.started)>=4*time.Second)
}
// A prolonged unresponsive reverse path must not permanently mask a newly
// restored direct path; any active app traffic switches the Iran sender back.
func (r *reverseICMP) expire(now time.Time){
 r.mu.Lock();defer r.mu.Unlock()
 if r.region=="iran"&&r.active&&r.demand&&!r.lastPoll.IsZero()&&now.Sub(r.lastPoll)>35*time.Second{
  r.active=false
  r.frames=nil;r.frameBytes=0
 }
 if r.region=="foreign"&&r.active&&!r.lastReply.IsZero()&&now.Sub(r.lastReply)>45*time.Second{
  r.active=false
 }
}
func (r *reverseICMP) snapshot()(string,int,uint64){
 r.mu.Lock();defer r.mu.Unlock()
 mode:="direct"
 if r.active{mode="reverse"}
 return mode,len(r.frames),r.dropped
}
var errReverseNoSecureSession=errors.New("reverse requires authenticated secure pairing")
