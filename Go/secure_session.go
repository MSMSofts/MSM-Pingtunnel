package pingtunnel

// V4 security envelope for v3 pairing identity:
// authenticated ephemeral X25519 -> HKDF directional AEAD keys and nonces,
// replay-protected sequenced packets, fail-closed negotiation, and bounded
// handshake retransmission. Physical regions never depend on Go client role.
import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "encoding/json"
 "os"
 "errors"
 "io"
 "net"
 "sync"
 "time"
 "golang.org/x/crypto/chacha20poly1305"
 "golang.org/x/crypto/hkdf"
)

var (
 secureControlMagic = [4]byte{'P','T','H','4'}
 secureDataMagic = [4]byte{'P','T','D','4'}
 ErrSecureNegotiation = errors.New("authenticated ephemeral secure session is not ready")
)
const(
 helloClient byte=1
 helloServer byte=2
 helloFinish byte=3
 helloAck byte=4
 controlMACSize=32
 secureHeaderSize=4+1+16+8
 replayBits=1024
)
// A fixed 1024-bit replay window, independent of session lifetime.
//
// The previous math/big.Int.Lsh implementation never masked old high bits.
// Its memory and per-packet CPU cost grew with EVERY authenticated packet,
// causing progressive latency during long, high-PPS UDP/QUIC sessions.
// Word shifts run in constant bounded work (16 uint64s) without allocations.
type secureReplay struct {
 highest uint64
 bits [replayBits / 64]uint64
}
func (r *secureReplay) accept(n uint64) bool {
 if n == 0 { return false }
 if r.highest == 0 {
  r.highest = n
  r.bits[0] = 1
  return true
 }
 if n > r.highest {
  delta := n - r.highest
  if delta >= replayBits {
   r.bits = [replayBits / 64]uint64{}
  } else {
   words := int(delta / 64)
   shift := uint(delta % 64)
   // Traverse high to low so each source word remains intact until read.
   for i := len(r.bits) - 1; i >= 0; i-- {
    if i < words {
     r.bits[i] = 0
     continue
    }
    value := r.bits[i-words] << shift
    if shift != 0 && i > words {
     value |= r.bits[i-words-1] >> (64 - shift)
    }
    r.bits[i] = value
   }
  }
  r.highest = n
  r.bits[0] |= 1
  return true
 }
 delta := r.highest - n
 if delta >= replayBits { return false }
 word := int(delta / 64)
 mask := uint64(1) << uint(delta % 64)
 if r.bits[word]&mask != 0 { return false }
 r.bits[word] |= mask
 return true
}
type sessionKeys struct{
 txAES,txX,rxAES,rxX cipher.AEAD
 txAESPrefix,rxAESPrefix [4]byte
 txXPrefix,rxXPrefix [16]byte
 id [16]byte
 seq uint64
 replay secureReplay
}
type secureSession struct{
 mu sync.Mutex
 root [32]byte
 region string
 peer net.IP
 preferred byte
 state byte // 0 uninitialized; 1 client hello; 2 client finish; 3 server hello; 4 ready
 clientID,serverID [16]byte
 localPrivate *ecdh.PrivateKey
 clientPublic,serverPublic []byte
 keys *sessionKeys
 confirmKey []byte
 lastRetry time.Time
 retryCount uint
 lastValid time.Time
 started time.Time
 errors uint64
 invalidFormatErrors uint64
 wrongSessionErrors uint64
 aeadTagErrors uint64
 replays uint64
 recoveries uint64
 // A verified new handshake is staged separately from the established
 // session. Replayed (but MAC-valid) ClientHellos cannot tear it down.
 pending *secureSession
 recent map[[16]byte]time.Time
 lastCandidate time.Time
 queued []pendingICMP
 queueBytes int
 queueDrops uint64
}
func newSecureSession(root []byte, region string, preferred byte)*secureSession{
 s:=&secureSession{region:region,preferred:preferred}
 copy(s.root[:],root)
 return s
}
func (s *secureSession) setPeer(address string)error{
 ip:=net.ParseIP(address)
 if ip==nil||ip.To4()==nil||ip.IsUnspecified()||ip.IsLoopback(){
  return errors.New("secure peer must be a real IPv4")
 }
 s.mu.Lock();defer s.mu.Unlock()
 s.peer=ip.To4()
 return nil
}
func (s *secureSession) acceptsPeer(ip net.IP)bool{
 s.mu.Lock();defer s.mu.Unlock()
 return ip!=nil && s.peer!=nil && ip.Equal(s.peer)
}
func (s *secureSession) ready()bool{
 s.mu.Lock();defer s.mu.Unlock()
 return s.state==4&&s.keys!=nil
}

// Authenticated inbound application traffic is evidence of a live peer,
// even if ICMP ping replies are selectively filtered or delayed.
func (s *secureSession) lastPeerTraffic() time.Time {
 s.mu.Lock();defer s.mu.Unlock()
 return s.lastValid
}
func (s *secureSession) resetLocked() {
 s.pending=nil
 s.state=0;s.keys=nil;s.confirmKey=nil;s.localPrivate=nil
 s.clientPublic=nil;s.serverPublic=nil
 s.clientID=[16]byte{};s.serverID=[16]byte{}
 s.lastRetry=time.Time{};s.retryCount=0
}
func (s *secureSession) initiateLocked()error{
 s.resetLocked()
 p,err:=ecdh.X25519().GenerateKey(rand.Reader)
 if err!=nil{return err}
 s.localPrivate=p
 s.clientPublic=p.PublicKey().Bytes()
 if _,err=rand.Read(s.clientID[:]);err!=nil{return err}
 s.state=1;s.started=time.Now()
 return nil
}
func (s *secureSession) authenticationKey()[]byte{
 k:=make([]byte,32)
 _,_ = io.ReadFull(hkdf.New(sha256.New,s.root[:],nil,[]byte("pingtunnel-v4/handshake-psk")),k)
 return k
}
func (s *secureSession) macPSK(message []byte)[]byte{
 mac:=hmac.New(sha256.New,s.authenticationKey())
 mac.Write(message)
 return mac.Sum(nil)
}
func confirmMAC(key []byte,body []byte)[]byte{
 mac:=hmac.New(sha256.New,key);mac.Write(body);return mac.Sum(nil)
}
func controlBody(typ byte,cid,sid [16]byte,pub []byte)[]byte{
 out:=make([]byte,0,5+16+16+len(pub))
 out=append(out,secureControlMagic[:]...)
 out=append(out,typ)
 out=append(out,cid[:]...)
 if typ!=helloClient{out=append(out,sid[:]...)}
 if len(pub)>0{out=append(out,pub...)}
 return out
}
func controlType(frame []byte)byte{
 if len(frame)<5||!bytes.Equal(frame[:4],secureControlMagic[:]){return 0}
 return frame[4]
}
func (s *secureSession) startClient(now time.Time)error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.region!="iran"{return errors.New("only Iran initiates direct ICMP handshake")}
 if s.state==0{return s.initiateLocked()}
 return nil
}
func (s *secureSession) outbound(now time.Time)([]byte,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.region!="iran" {return nil,nil}
 if s.state==0{
  if err:=s.initiateLocked();err!=nil{return nil,err}
 }
 if s.state==4{return nil,nil}
 // Exponential capped retry with small random jitter (one ICMP attempt at
 // most per eligible heartbeat, never an unbounded busy retry loop).
 base:=time.Second<<minInt(int(s.retryCount),3)
 if base>8*time.Second{base=8*time.Second}
 if !s.lastRetry.IsZero()&&now.Sub(s.lastRetry)<base{return nil,nil}
 var body []byte
 switch s.state{
 case 1:body=controlBody(helloClient,s.clientID,[16]byte{},s.clientPublic)
 case 2:body=controlBody(helloFinish,s.clientID,s.serverID,nil)
 default:return nil,nil
 }
 var tag []byte
 if s.state==2{tag=confirmMAC(s.confirmKey,body)}else{tag=s.macPSK(body)}
 s.lastRetry=now
 if s.retryCount<4{s.retryCount++}
 return append(body,tag...),nil
}
func minInt(a,b int)int{if a<b{return a};return b}
func verifyMAC(key,body,mac []byte)bool{
 if len(mac)!=32{return false}
 expected:=confirmMAC(key,body)
 return hmac.Equal(mac,expected)
}
func (s *secureSession) deriveLocked(peerPub []byte)error{
 pub,err:=ecdh.X25519().NewPublicKey(peerPub)
 if err!=nil{return err}
 shared,err:=s.localPrivate.ECDH(pub)
 if err!=nil{return err}
 // IDs and ephemeral pubkeys are transcript-bound, so a recorded PSK alone
 // cannot retrospectively recover a session without erased X25519 secrets.
 transcript:=make([]byte,0,16+16+32+32)
 transcript=append(transcript,s.clientID[:]...)
 transcript=append(transcript,s.serverID[:]...)
 transcript=append(transcript,s.clientPublic...)
 transcript=append(transcript,s.serverPublic...)
 digest:=sha256.Sum256(transcript)
 kdf:=func(label string,n int)([]byte,error){
  out:=make([]byte,n)
  _,err:=io.ReadFull(hkdf.New(sha256.New,shared,s.root[:],append([]byte("pingtunnel-v4/"+label+"/"),digest[:]...)),out)
  return out,err
 }
 confirm,err:=kdf("finish",32);if err!=nil{return err}
 s.confirmKey=confirm
 k:=&sessionKeys{}
 copy(k.id[:],digest[:16])
 keyFor:=func(dir,alg string)(cipher.AEAD,error){
  raw,err:=kdf(dir+"/"+alg,32)
  if err!=nil{return nil,err}
  if alg=="aes"{
   blk,e:=aes.NewCipher(raw)
   if e!=nil{return nil,e}
   return cipher.NewGCM(blk)
  }
  return chacha20poly1305.NewX(raw)
 }
 tx,rx:="iran-to-foreign","foreign-to-iran"
 if s.region=="foreign"{tx,rx=rx,tx}
 if k.txAES,err=keyFor(tx,"aes");err!=nil{return err}
 if k.rxAES,err=keyFor(rx,"aes");err!=nil{return err}
 if k.txX,err=keyFor(tx,"xchacha");err!=nil{return err}
 if k.rxX,err=keyFor(rx,"xchacha");err!=nil{return err}
 p,err:=kdf(tx+"/aes-prefix",4);if err!=nil{return err};copy(k.txAESPrefix[:],p)
 p,err=kdf(rx+"/aes-prefix",4);if err!=nil{return err};copy(k.rxAESPrefix[:],p)
 p,err=kdf(tx+"/x-prefix",16);if err!=nil{return err};copy(k.txXPrefix[:],p)
 p,err=kdf(rx+"/x-prefix",16);if err!=nil{return err};copy(k.rxXPrefix[:],p)
 // Erase ephemeral private-key reference immediately after deriving keys.
 s.localPrivate=nil
 s.keys=k
 return nil
}
// authenticated Hello/HelloReply use PSK; Finish/Ack use ephemeral ECDH
// confirmation key. No decrypted application data is accepted until ready.
func (s *secureSession) handle(frame []byte,now time.Time)([]byte,error){
 typ:=controlType(frame)
 if typ==0{return nil,errors.New("not a v4 secure control frame")}
 s.mu.Lock();defer s.mu.Unlock()
 if len(frame)<5+16+32{return nil,errors.New("short handshake")}
 body,tag:=frame[:len(frame)-32],frame[len(frame)-32:]
 // Protect established sessions from a valid-but-recorded old ClientHello.
 // An authenticated reconnect is prepared using a *candidate* handshake.
 // Switching keys happens only AFTER a fresh ephemeral Finish proof.
 if s.region=="foreign" && s.state==4 {
  if typ==helloClient {
   if len(body)!=5+16+32 || !verifyMAC(s.authenticationKey(),body,tag) {
    s.errors++
    return nil,errors.New("unauthenticated reconnect hello")
   }
   var cid [16]byte
   copy(cid[:],body[5:21])
   if cid==s.clientID {return nil,nil}
   if _,seen:=s.recent[cid];seen{return nil,nil}
   if s.pending!=nil && s.pending.clientID==cid {
    return s.pending.handle(frame,now)
   }
   // One candidate at a time, with a deadline and arrival rate limit.
   if s.pending!=nil && now.Sub(s.pending.started)<5*time.Second{return nil,nil}
   if !s.lastCandidate.IsZero() && now.Sub(s.lastCandidate)<time.Second{return nil,nil}
   candidate:=newSecureSession(s.root[:],"foreign",s.preferred)
   candidate.peer=append(net.IP(nil),s.peer...)
   result,err:=candidate.handle(frame,now)
   if err!=nil{return nil,err}
   s.pending=candidate
   s.lastCandidate=now
   return result,nil
  }
  if typ==helloFinish && s.pending!=nil {
   result,err:=s.pending.handle(frame,now)
   if err!=nil{s.errors++;s.aeadTagErrors++;return nil,err}
   if s.pending.state==4 {
    // Keep only a bounded recent-ID memory; old HMACed hellos are rejected
    // without allocating a candidate or disturbing the active data path.
    if s.recent==nil{s.recent=make(map[[16]byte]time.Time)}
    s.recent[s.clientID]=now
    if len(s.recent)>256 {
     for key,when:=range s.recent {
      if now.Sub(when)>10*time.Minute {delete(s.recent,key)}
     }
     if len(s.recent)>256 {
      // Retain at least the current/previous active IDs; older entries
      // are still harmless because candidate keys are isolated.
      for key:=range s.recent {if key!=s.clientID{delete(s.recent,key);break}}
     }
    }
    s.keys=s.pending.keys
    s.clientID=s.pending.clientID
    s.serverID=s.pending.serverID
    s.clientPublic=s.pending.clientPublic
    s.serverPublic=s.pending.serverPublic
    s.confirmKey=s.pending.confirmKey
    s.state=4
    s.lastValid=now
    s.pending=nil
   }
   return result,nil
  }
 }
 if typ==helloClient{
  if s.region!="foreign"||len(body)!=5+16+32{return nil,errors.New("invalid client hello")}
  var cid [16]byte;copy(cid[:],body[5:21])
  if !verifyMAC(s.authenticationKey(),body,tag){s.errors++;return nil,errors.New("unauthenticated client hello")}
  if s.state==4 && now.Sub(s.lastValid)<20*time.Second{return nil,nil}
  if s.state==3 && cid==s.clientID {
   reply:=controlBody(helloServer,s.clientID,s.serverID,s.serverPublic)
   return append(reply,s.macPSK(reply)...),nil
  }
  if s.state==3 && now.Sub(s.started)<3*time.Second{return nil,nil}
  // Rate-limit malicious new handshakes; no allocation until MAC verified.
  if now.Sub(s.started)<time.Second{return nil,nil}
  s.resetLocked()
  s.clientID=cid;s.clientPublic=append([]byte(nil),body[21:53]...)
  p,err:=ecdh.X25519().GenerateKey(rand.Reader)
  if err!=nil{return nil,err}
  s.localPrivate=p;s.serverPublic=p.PublicKey().Bytes()
  if _,err=rand.Read(s.serverID[:]);err!=nil{return nil,err}
  if err=s.deriveLocked(s.clientPublic);err!=nil{return nil,err}
  s.state=3;s.started=now
  reply:=controlBody(helloServer,s.clientID,s.serverID,s.serverPublic)
  return append(reply,s.macPSK(reply)...),nil
 }
 if typ==helloServer{
  if s.region!="iran"||s.state!=1||len(body)!=5+16+16+32{return nil,errors.New("unexpected server hello")}
  if !bytes.Equal(body[5:21],s.clientID[:]) || !verifyMAC(s.authenticationKey(),body,tag){
   s.errors++
   return nil,errors.New("untrusted server hello")
  }
  copy(s.serverID[:],body[21:37])
  s.serverPublic=append([]byte(nil),body[37:69]...)
  if err:=s.deriveLocked(s.serverPublic);err!=nil{return nil,err}
  s.state=2;s.retryCount=0;s.lastRetry=time.Time{}
  reply:=controlBody(helloFinish,s.clientID,s.serverID,nil)
  return append(reply,confirmMAC(s.confirmKey,reply)...),nil
 }
 if typ==helloFinish{
  if s.region!="foreign"||(s.state!=3&&s.state!=4)||len(body)!=5+16+16{return nil,errors.New("unexpected client finish")}
  if !bytes.Equal(body[5:21],s.clientID[:])||!bytes.Equal(body[21:37],s.serverID[:])||!verifyMAC(s.confirmKey,body,tag){
   s.errors++
   return nil,errors.New("invalid client finish")
  }
  s.state=4;s.lastValid=now
  reply:=controlBody(helloAck,s.clientID,s.serverID,nil)
  return append(reply,confirmMAC(s.confirmKey,reply)...),nil
 }
 if typ==helloAck{
  if s.region!="iran"||s.state!=2||len(body)!=5+16+16{return nil,errors.New("unexpected server ack")}
  if !bytes.Equal(body[5:21],s.clientID[:])||!bytes.Equal(body[21:37],s.serverID[:])||!verifyMAC(s.confirmKey,body,tag){
   s.errors++
   return nil,errors.New("untrusted server ack")
  }
  s.state=4;s.lastValid=now
  return nil,nil
 }
 return nil,errors.New("unknown control type")
}
// Allocate a unique sequence number while locked, but do not hold the
// session mutex during AES-GCM / XChaCha20-Poly1305 sealing. Concurrent
// UDP/QUIC senders may otherwise serialize behind an expensive AEAD call.
// sessionKeys and AEADs are immutable after publication; a rekey swaps the
// pointer rather than mutating an in-flight sender's cipher.
func (s *secureSession) encrypt(plain []byte)([]byte,error){
 s.mu.Lock()
 if s.state!=4||s.keys==nil {
  s.mu.Unlock()
  return nil,ErrSecureNegotiation
 }
 k:=s.keys
 if k.seq==^uint64(0) {
  s.mu.Unlock()
  return nil,errors.New("sequence overflow, rekey required")
 }
 k.seq++
 seq:=k.seq
 alg:=s.preferred
 var a cipher.AEAD
 var nonce []byte
 switch alg{
 case autoAES:a=k.txAES;nonce=make([]byte,12);copy(nonce,k.txAESPrefix[:])
 case autoXChaCha:a=k.txX;nonce=make([]byte,24);copy(nonce,k.txXPrefix[:])
 default:
  s.mu.Unlock()
  return nil,errors.New("invalid selected cipher")
 }
 binary.BigEndian.PutUint64(nonce[len(nonce)-8:],seq)
 head:=make([]byte,secureHeaderSize)
 copy(head[:4],secureDataMagic[:]);head[4]=alg
 copy(head[5:21],k.id[:]);binary.BigEndian.PutUint64(head[21:29],seq)
 s.mu.Unlock()
 return a.Seal(head,nonce,plain,head),nil
}

// Authenticate outside the session mutex. When Open completes, verify the
// same session is still active BEFORE admitting sequence numbers into the
// replay window. An in-flight old-session packet after a rekey must not be
// accepted or update freshness of the replacement session.
func (s *secureSession) decrypt(frame []byte)([]byte,error){
 s.mu.Lock()
 if s.state!=4||s.keys==nil {
  s.mu.Unlock()
  return nil,ErrSecureNegotiation
 }
 if len(frame)<secureHeaderSize+16||!bytes.Equal(frame[:4],secureDataMagic[:]){
  s.errors++
  s.invalidFormatErrors++
  s.mu.Unlock()
  return nil,errors.New("v4 authenticated frame required")
 }
 k:=s.keys
 if !hmac.Equal(frame[5:21],k.id[:]){
  s.errors++
  s.wrongSessionErrors++
  s.mu.Unlock()
  return nil,errors.New("wrong session")
 }
 seq:=binary.BigEndian.Uint64(frame[21:29])
 if seq==0 {
  s.mu.Unlock()
  return nil,errors.New("invalid sequence")
 }
 var a cipher.AEAD
 var nonce []byte
 switch frame[4]{
 case autoAES:a=k.rxAES;nonce=make([]byte,12);copy(nonce,k.rxAESPrefix[:])
 case autoXChaCha:a=k.rxX;nonce=make([]byte,24);copy(nonce,k.rxXPrefix[:])
 default:
  s.mu.Unlock()
  return nil,errors.New("invalid cipher ID")
 }
 binary.BigEndian.PutUint64(nonce[len(nonce)-8:],seq)
 s.mu.Unlock()

 plaintext,err:=a.Open(nil,nonce,frame[secureHeaderSize:],frame[:secureHeaderSize])
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.state!=4||s.keys!=k {
  return nil,ErrSecureNegotiation
 }
 if err!=nil{s.errors++;return nil,err}
 if !k.replay.accept(seq){s.replays++;return nil,errors.New("replay or out-of-window sequence")}
 s.lastValid=time.Now()
 return plaintext,nil
}
func (s *secureSession) resetForTransportChange() {
 s.mu.Lock();defer s.mu.Unlock()
 s.resetLocked()
 s.recoveries++
}
func (s *secureSession) recoverIfStale(now time.Time,hasPendingTraffic bool)bool{
 s.mu.Lock();defer s.mu.Unlock()
 if s.region!="iran"||s.state!=4||s.keys==nil{return false}
 // Only reset after a proven unhealthy period with demand. Silence while
 // idle must not trigger rekey and interrupt healthy quiet tunnels.
 if !hasPendingTraffic||now.Sub(s.lastValid)<35*time.Second{return false}
 s.resetLocked()
 s.recoveries++
 return true
}
// Bounded 2 MiB / 256 frame / 12s queue for app packets generated while a
// fresh X25519 session is negotiated. Oldest items are dropped explicitly and
// counted rather than allocating unbounded memory or losing all UDP startup
// datagrams. TCP reliability is still owned by its protocol's FrameMgr.
type pendingICMP struct{
 raw []byte
 peer *net.IPAddr
 id,seq,proto int
 arrival time.Time
}
const (
 pendingMaxFrames = 256
 pendingMaxBytes = 2 * 1024 * 1024
 pendingLifetime = 12 * time.Second
)
func (s *secureSession) queuePacket(msg pendingICMP) {
 s.mu.Lock()
 defer s.mu.Unlock()
 if len(msg.raw)==0 || len(msg.raw)>10240 {s.queueDrops++;return}
 msg.raw=append([]byte(nil),msg.raw...)
 if msg.peer!=nil {
  ip:=append(net.IP(nil),msg.peer.IP...)
  msg.peer=&net.IPAddr{IP:ip,Zone:msg.peer.Zone}
 }
 if msg.arrival.IsZero(){msg.arrival=time.Now()}
 for len(s.queued)>0 && (len(s.queued)>=pendingMaxFrames || s.queueBytes+len(msg.raw)>pendingMaxBytes) {
  s.queueBytes-=len(s.queued[0].raw)
  s.queued[0]=pendingICMP{}
  s.queued=s.queued[1:]
  s.queueDrops++
 }
 s.queueBytes+=len(msg.raw)
 s.queued=append(s.queued,msg)
}
func (s *secureSession) drainPending(now time.Time)[]pendingICMP{
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.state!=4{return nil}
 pending:=s.queued
 s.queued=nil
 s.queueBytes=0
 out:=pending[:0]
 for _,p:=range pending {
  if now.Sub(p.arrival)>pendingLifetime{s.queueDrops++;continue}
  out=append(out,p)
 }
 return out
}
func (s *secureSession) pushBack(p pendingICMP) {
 s.queuePacket(p)
}

type sessionStats struct{
 Secure bool
 ReplayDrops,AuthenticationFailures,Recoveries,QueuedPackets,QueuedDrops uint64
}
func (s *secureSession) stats()sessionStats{
 s.mu.Lock();defer s.mu.Unlock()
 return sessionStats{Secure:s.state==4,ReplayDrops:s.replays,
  AuthenticationFailures:s.errors,Recoveries:s.recoveries,QueuedPackets:uint64(len(s.queued)),QueuedDrops:s.queueDrops}
}

type secureStatus struct{
 ConfigSchema int `json:"config_schema"`
 WireVersion int `json:"wire_version"`
 Region string `json:"region"`
 ICMPDirection string `json:"icmp_direction,omitempty"`
 ReverseProbeAgeSeconds int64 `json:"reverse_probe_age_seconds"`
 ReverseQueuePackets int `json:"reverse_queue_packets"`
 ReverseQueueBytes int `json:"reverse_queue_bytes"`
 ReverseQueuePeak int `json:"reverse_queue_peak"`
 ReverseQueueDrops uint64 `json:"reverse_queue_drops"`
    ReverseOversizedDrops uint64 `json:"reverse_oversized_drops"`
 ReverseWriteFailures uint64 `json:"reverse_write_failures"`
 ICMPWriteFailures uint64 `json:"icmp_write_failures"`
 ICMPWriteEMSGSIZE uint64 `json:"icmp_write_emsgsize"`
 ICMPUserspaceRequests uint64 `json:"icmp_userspace_echo_requests"`
 ICMPUserspaceReplies uint64 `json:"icmp_userspace_echo_replies"`
 ICMPCurrentPPS uint64 `json:"icmp_userspace_pps"`
 UDPQueueOverflowDrops uint64 `json:"udp_dispatch_overflow_drops"`
 TCPQueueOverflowDrops uint64 `json:"tcp_dispatch_overflow_drops"`
 UDPQueueMaxDelayMs uint64 `json:"udp_dispatch_queue_max_delay_ms"`
 TCPQueueMaxDelayMs uint64 `json:"tcp_dispatch_queue_max_delay_ms"`
 UDPQueueDelayedOver250ms uint64 `json:"udp_dispatch_delayed_over_250ms"`
 TCPQueueDelayedOver250ms uint64 `json:"tcp_dispatch_delayed_over_250ms"`
 UDPTruncatedDatagrams uint64 `json:"udp_truncated_datagrams"`
 ICMPPeakPPS uint64 `json:"icmp_userspace_peak_pps"`
 ReversePathProofs uint64 `json:"reverse_path_proofs"`
 ReverseReturnAttempts uint64 `json:"reverse_return_attempts"`
 ReversePollRequests uint64 `json:"reverse_polls_sent"`
 ReversePollsCoalesced uint64 `json:"reverse_polls_coalesced"`
 ReverseBacklogWakesSent uint64 `json:"reverse_backlog_wakes_sent"`
 ReverseBacklogWakesAccepted uint64 `json:"reverse_backlog_wakes_accepted"`
 ReverseBacklogWakesRateLimited uint64 `json:"reverse_backlog_wakes_rate_limited"`
 ReverseWakeBurstRemainingMs int64 `json:"reverse_wake_burst_remaining_ms"`
 ReverseRemoteQueueHintDepth int `json:"reverse_remote_queue_hint_depth"`
 ReverseRemoteQueueHintOldestMs int `json:"reverse_remote_queue_hint_oldest_ms"`
 ReverseRemoteQueueHintBytes int `json:"reverse_remote_queue_hint_bytes"`
 ReverseRemoteQueueHintAgeMs int64 `json:"reverse_remote_queue_hint_age_ms"`
 ReverseQueueHintsReceived uint64 `json:"reverse_queue_hints_received"`
 ReverseQueueHintsRejected uint64 `json:"reverse_queue_hints_rejected"`
 ReversePollBackoffRemainingMs int64 `json:"reverse_poll_backoff_remaining_ms"`
 DirectProbeChecks uint64 `json:"direct_probe_checks"`
 DirectPathProofs uint64 `json:"direct_path_proofs"`
 DirectLastProofAgeSeconds int64 `json:"direct_last_proof_age_seconds"`
 AutoLastSwitchAgeSeconds int64 `json:"auto_last_switch_age_seconds"`
 SmartRotationIntervalSeconds uint64 `json:"smart_rotation_interval_seconds"`
 SmartRotationDue bool `json:"smart_rotation_due"`
 SmartRotationCount uint64 `json:"smart_rotation_count"`
 SmartRotationRetryCount uint64 `json:"smart_rotation_retries"`
 SmartRotationLastReason string `json:"smart_rotation_last_reason,omitempty"`
 SmartDirectProofConfirmations int `json:"smart_direct_proof_confirmations"`
 AutoRoutePolicy string `json:"auto_route_policy"`
 AutoPreferredReverseReturns uint64 `json:"auto_preferred_reverse_returns"`
 AutoReverseProofConfirmations int `json:"auto_reverse_proof_confirmations"`
 AutoPendingReverseHandoff bool `json:"auto_pending_reverse_handoff"`
 AutoReverseLastProofAgeMs int64 `json:"auto_reverse_last_proof_age_ms"`
 ICMPFragmentedDatagrams uint64 `json:"icmp_fragmented_datagrams"`
 ICMPReassembledDatagrams uint64 `json:"icmp_reassembled_datagrams"`
 ICMPFragmentDrop uint64 `json:"icmp_fragment_drops"`
 ICMPFECParityGenerated uint64 `json:"icmp_fec_parity_generated"`
 ICMPFECRecovered uint64 `json:"icmp_fec_recovered_datagrams"`
 ReversePollEchoReflections uint64 `json:"reverse_poll_echo_reflections"`
 ReverseDataEchoReflections uint64 `json:"reverse_data_echo_reflections"`
 ReversePingEchoReflections uint64 `json:"reverse_ping_echo_reflections"`
 ReverseOtherEchoReflections uint64 `json:"reverse_other_echo_reflections"`
 DirectDataEchoReflections uint64 `json:"direct_data_echo_reflections"`
 DirectPingEchoReflections uint64 `json:"direct_ping_echo_reflections"`
 DirectOtherEchoReflections uint64 `json:"direct_other_echo_reflections"`
 ReverseEchoCacheExpired uint64 `json:"reverse_echo_cache_expired"`
 ReverseEchoCacheCapacityEvicted uint64 `json:"reverse_echo_cache_capacity_evicted"`
 ReverseDataEchoCacheEntries int `json:"reverse_data_echo_cache_entries"`
 ReverseReplayCapacityRejects uint64 `json:"reverse_replay_capacity_rejections"`
 ReversePollIntervalMs int `json:"reverse_poll_interval_ms"`
 ReverseOldestQueueAgeMs int64 `json:"reverse_oldest_queue_age_ms"`
 ReverseLastDeliveryDelayMs int64 `json:"reverse_last_delivery_delay_ms"`
 ReverseMaxDeliveryDelayMs int64 `json:"reverse_max_delivery_delay_ms"`
 ReverseDeliveredFrames uint64 `json:"reverse_delivered_frames"`
 ReverseDelayedFrames uint64 `json:"reverse_delayed_frames"`
 ReverseVeryDelayedFrames uint64 `json:"reverse_very_delayed_frames"`
 ReverseMeanDeliveryDelayMs int64 `json:"reverse_mean_delivery_delay_ms"`
 ReverseP95DeliveryDelayMs int64 `json:"reverse_p95_delivery_delay_ms"`
 ReverseDeliveryDelaySamples int `json:"reverse_delivery_delay_samples"`
 ReverseLastDeliveryAgeSeconds int64 `json:"reverse_last_delivery_age_seconds"`
 ReverseLastOutboundDataAgeMs int64 `json:"reverse_last_outbound_data_age_ms"`
 ReverseLastDataAge int64 `json:"reverse_last_data_age_seconds"`
 AutoFallbackCount uint64 `json:"auto_direct_fallback_count"`
 AutoFallbackReason string `json:"auto_direct_fallback_reason,omitempty"`
 State string `json:"state"`
 LastValidAgeSeconds int64 `json:"last_valid_age_seconds"`
 PendingRekey bool `json:"pending_rekey"`
 ReplayDrops uint64 `json:"replay_drops"`
 AuthFailures uint64 `json:"authentication_failures"`
 AuthInvalidFormat uint64 `json:"authentication_invalid_frame_failures"`
 AuthWrongSession uint64 `json:"authentication_wrong_session_failures"`
 AuthTagFailures uint64 `json:"authentication_aead_tag_failures"`
 Recoveries uint64 `json:"recoveries"`
 PendingPackets uint64 `json:"pending_packets"`
 ExpiredOrOverflowPackets uint64 `json:"expired_or_overflow_packets"`
}
func (s *secureSession) status()secureStatus{
 s.mu.Lock();defer s.mu.Unlock()
 phase:="negotiating"
 if s.state==4 {phase="authenticated"}
 if s.state==0 {phase="not-started"}
 age:=int64(-1)
 if !s.lastValid.IsZero(){age=int64(time.Since(s.lastValid).Seconds())}
 return secureStatus{
  ConfigSchema:3,WireVersion:4,Region:s.region,State:phase,
  LastValidAgeSeconds:age,PendingRekey:s.pending!=nil,
  ReplayDrops:s.replays,AuthFailures:s.errors,
  AuthInvalidFormat:s.invalidFormatErrors,AuthWrongSession:s.wrongSessionErrors,
  AuthTagFailures:s.aeadTagErrors,
  Recoveries:s.recoveries,PendingPackets:uint64(len(s.queued)),
  ExpiredOrOverflowPackets:s.queueDrops,
 }
}
func (s *secureSession) writeStatus(path string) {
 s.writeStatusWithDirection(path,"direct",-1,reverseDiagnostics{LastUsefulFrameAgeSeconds:-1})
}
func (s *secureSession) writeStatusWithDirection(path string,direction string,reverseProbeAge int64,diag reverseDiagnostics,policy ...string) {
 report:=s.status()
 report.ICMPDirection=direction
 report.ReverseProbeAgeSeconds=reverseProbeAge
 report.ReverseQueuePackets=diag.Pending
 report.ReverseQueueBytes=diag.PendingBytes
 report.ReverseQueuePeak=diag.QueuePeak
 report.ReverseQueueDrops=diag.QueueDrops
 report.ReverseOversizedDrops=diag.OversizedDrops
 report.ReverseWriteFailures=diag.FailedReplies
 report.ICMPWriteFailures=icmpWriteErrors.Load()
 report.ICMPWriteEMSGSIZE=icmpMessageTooLong.Load()
 report.ICMPUserspaceRequests=icmpRequestsSent.Load()
 report.ICMPUserspaceReplies=icmpRepliesSent.Load()
 report.UDPQueueOverflowDrops=udpIngressOverflowDrops.Load()
 report.TCPQueueOverflowDrops=tcpIngressOverflowDrops.Load()
 report.UDPQueueMaxDelayMs=mixedUDPQueueMaxDelayMs.Load()
 report.TCPQueueMaxDelayMs=mixedTCPQueueMaxDelayMs.Load()
 report.UDPQueueDelayedOver250ms=mixedUDPQueueOver250ms.Load()
 report.TCPQueueDelayedOver250ms=mixedTCPQueueOver250ms.Load()
 report.UDPTruncatedDatagrams=udpTruncatedDatagrams.Load()
 report.ICMPCurrentPPS,report.ICMPPeakPPS=icmpSentRate(time.Now())
 report.ReversePathProofs=diag.ReverseProofs
 report.ReverseReturnAttempts=diag.ReverseSwitchAttempts
 report.ReversePollRequests=diag.PollRequests
 report.ReversePollsCoalesced=diag.PollsSkippedByData
 report.ReverseBacklogWakesSent=diag.BacklogWakeSent
 report.ReverseBacklogWakesAccepted=diag.BacklogWakeAccepted
 report.ReverseBacklogWakesRateLimited=diag.BacklogWakeRateLimited
 report.ReverseWakeBurstRemainingMs=diag.BacklogWakeActiveMs
 report.ReverseRemoteQueueHintDepth=diag.QueueHintDepth
 report.ReverseRemoteQueueHintOldestMs=diag.QueueHintAgeMs
 report.ReverseRemoteQueueHintBytes=diag.QueueHintBytes
 report.ReverseRemoteQueueHintAgeMs=diag.QueueHintAgeSinceReceivedMs
 report.ReverseQueueHintsReceived=diag.QueueHintsReceived
 report.ReverseQueueHintsRejected=diag.QueueHintsRejected
 report.ReversePollBackoffRemainingMs=diag.PollBackoffRemainingMs
 report.DirectProbeChecks=diag.DirectProbeChecks
 report.DirectPathProofs=diag.DirectPathProofs
 report.DirectLastProofAgeSeconds=diag.DirectLastProofAgeSeconds
 report.AutoLastSwitchAgeSeconds=diag.LastSwitchAgeSeconds
 report.SmartRotationIntervalSeconds=uint64(smartRotationInterval.Seconds())
 report.SmartRotationDue=diag.RotationDue
 report.SmartRotationCount=diag.ScheduledRotations
 report.SmartRotationRetryCount=diag.RotationRetryCount
 report.SmartRotationLastReason=diag.LastRotationReason
 report.SmartDirectProofConfirmations=diag.DirectProofConfirmations
 if len(policy)>0 {
    switch policy[0] {
    case "auto":report.AutoRoutePolicy="reverse_preferred_direct_on_failure"
    case "auto_direct":report.AutoRoutePolicy="direct_preferred_reverse_on_failure"
    case "reverse":report.AutoRoutePolicy="manual_reverse"
    case "direct":report.AutoRoutePolicy="manual_direct"
    }
 }
 report.AutoPreferredReverseReturns=diag.PreferredReverseReturns
 report.AutoReverseProofConfirmations=diag.ReverseProofConfirmations
 report.AutoPendingReverseHandoff=diag.PendingPreferredReverse
 report.AutoReverseLastProofAgeMs=diag.LastReverseProofAgeMs
 report.ICMPFragmentedDatagrams=icmpFragmentedDatagrams.Load()
 report.ICMPReassembledDatagrams=icmpReassembledDatagrams.Load()
 report.ICMPFragmentDrop=icmpFragmentDropped.Load()
 report.ICMPFECParityGenerated=icmpFECParitySent.Load()
 report.ICMPFECRecovered=icmpFECRecovered.Load()
 report.ReversePollEchoReflections=diag.ReflectedPolls
 report.ReverseDataEchoReflections=diag.ReflectedDataEchoes
 report.ReversePingEchoReflections=diag.ReflectedPingEchoes
 report.ReverseOtherEchoReflections=diag.ReflectedOtherEchoes
 report.DirectDataEchoReflections=diag.DirectReflectedDataEchoes
 report.DirectPingEchoReflections=diag.DirectReflectedPingEchoes
 report.DirectOtherEchoReflections=diag.DirectReflectedOtherEchoes
 report.ReverseEchoCacheExpired=diag.ExpiredEchoSignatures
 report.ReverseEchoCacheCapacityEvicted=diag.CapacityEvictedEchoSignatures
 report.ReverseDataEchoCacheEntries=diag.OutboundEchoCacheEntries
 report.ReverseReplayCapacityRejects=diag.ReplayCapacityRejects
 report.ReversePollIntervalMs=diag.PollIntervalMillis
 report.ReverseOldestQueueAgeMs=diag.OldestQueueAgeMs
 report.ReverseLastDeliveryDelayMs=diag.LastQueueDelayMs
 report.ReverseMaxDeliveryDelayMs=diag.MaxQueueDelayMs
 report.ReverseDeliveredFrames=diag.DeliveredFrames
 report.ReverseDelayedFrames=diag.DelayedFrames
 report.ReverseVeryDelayedFrames=diag.VeryDelayedFrames
 report.ReverseMeanDeliveryDelayMs=diag.MeanQueueDelayMs
 report.ReverseP95DeliveryDelayMs=diag.P95QueueDelayMs
 report.ReverseDeliveryDelaySamples=diag.DeliveryDelaySampleCount
 report.ReverseLastDeliveryAgeSeconds=diag.LastDeliveryAgeSeconds
 report.ReverseLastOutboundDataAgeMs=diag.LastOutboundDataAgeMs
 report.ReverseLastDataAge=diag.LastUsefulFrameAgeSeconds
 report.AutoFallbackCount=diag.FallbackCount
 report.AutoFallbackReason=diag.FallbackReason
 encoded,err:=json.Marshal(report)
 if err!=nil{return}
 tmp:=path+".pending"
 if err=os.WriteFile(tmp,encoded,0600);err!=nil{return}
 if err=os.Rename(tmp,path);err!=nil{_ = os.Remove(tmp)}
}
