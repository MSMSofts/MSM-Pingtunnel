package pingtunnel

import (
 "bytes"
 "crypto/rand"
 "net"
 "testing"
 "time"
)

func TestRecordedClientHelloCannotDisconnectEstablishedTunnel(t *testing.T){
 iran,foreign:=newSecurePair(t)
 old:=controlBody(helloClient,foreign.sec.clientID,[16]byte{},foreign.sec.clientPublic)
 recorded:=append(old,foreign.sec.macPSK(old)...)
 if result,err:=foreign.ReceiveSecureControl(recorded,time.Now().Add(time.Minute));err!=nil||len(result)!=0 {
  t.Fatalf("historical ClientHello was not ignored: response=%d err=%v",len(result),err)
 }
 if !foreign.SecureReady(){t.Fatal("recorded hello tore down authenticated data session")}
 f,err:=iran.Encrypt([]byte("existing secure traffic"))
 if err!=nil{t.Fatal(err)}
 if b,err:=foreign.Decrypt(f);err!=nil||string(b)!="existing secure traffic"{
  t.Fatalf("established traffic disrupted after replay: %v",err)
 }
}

func TestNewClientHelloRequiresFinishBeforeReplacingLiveSession(t *testing.T){
 iran,foreign:=newSecurePair(t)
 var otherID [16]byte
 if _,err:=rand.Read(otherID[:]);err!=nil{t.Fatal(err)}
 challenge:=controlBody(helloClient,otherID,[16]byte{},foreign.sec.clientPublic)
 challenge=append(challenge,foreign.sec.macPSK(challenge)...)
 now:=time.Now().Add(time.Minute)
 reply,err:=foreign.ReceiveSecureControl(challenge,now)
 if err!=nil||len(reply)==0{t.Fatalf("new candidate challenge failed: %v",err)}
 if !foreign.SecureReady(){t.Fatal("mere PSK-authenticated hello reset live session")}
 if foreign.sec.pending==nil{t.Fatal("new hello must be staged as candidate")}
 invalid:=controlBody(helloFinish,otherID,foreign.sec.pending.serverID,nil)
 invalid=append(invalid,foreign.sec.macPSK(invalid)...)
 if _,err:=foreign.ReceiveSecureControl(invalid,now);err==nil {
  t.Fatal("candidate Finish did not require the X25519-derived confirmation")
 }
 if !foreign.SecureReady(){t.Fatal("failed candidate Finish invalidated live session")}
 frame,_:=iran.Encrypt([]byte("original frame"))
 if p,err:=foreign.Decrypt(frame);err!=nil||!bytes.Equal(p,[]byte("original frame")){
  t.Fatal("candidate handshake interrupted authenticated stream",err)
 }
}

func TestPendingBufferBoundsAndTimeout(t *testing.T){
 key:=pairedTestKey(t)
 iran,_:=NewCryptoConfig(AUTO,key)
 foreign,_:=NewCryptoConfig(AUTO,key)
 if err:=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
 if err:=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
 if err:=iran.BindSecurePeer("203.0.113.5");err!=nil{t.Fatal(err)}
 if err:=foreign.BindSecurePeer("203.0.113.4");err!=nil{t.Fatal(err)}
 for i:=0;i<280;i++{
  iran.sec.queuePacket(pendingICMP{raw:bytes.Repeat([]byte("D"),8192),peer:&net.IPAddr{IP:net.ParseIP("203.0.113.5")},id:42,seq:i,proto:8})
 }
 if n:=len(iran.sec.queued);n>pendingMaxFrames{t.Fatalf("unbounded packet queue: %d",n)}
 if iran.sec.queueBytes>pendingMaxBytes{t.Fatal("unbounded queue bytes")}
 if iran.sec.queueDrops==0{t.Fatal("overflow was not counted")}
 if a:=iran.sec.drainPending(time.Now());len(a)!=0{t.Fatal("must not emit data before authenticated handshake")}
 handshakeEphemeral(t,iran,foreign)
 pending:=iran.sec.drainPending(time.Now())
 if len(pending)==0||len(pending)>pendingMaxFrames{t.Fatalf("unexpected pending count=%d",len(pending))}
 for _,p:=range pending{
  enc,err:=iran.Encrypt(p.raw);if err!=nil{t.Fatal(err)}
  plain,err:=foreign.Decrypt(enc)
  if err!=nil||!bytes.Equal(plain,p.raw){t.Fatal("queued frame failed authenticated delivery",err)}
 }
 iran.sec.queuePacket(pendingICMP{raw:[]byte("stale"),arrival:time.Now().Add(-pendingLifetime-time.Second)})
 if len(iran.sec.drainPending(time.Now()))!=0{t.Fatal("expired datagram was replayed")}
}

func TestFailedRenegotiationPreservesOldSessionUnderLoss(t *testing.T){
 iran,foreign:=newSecurePair(t)
 now:=time.Now().Add(time.Minute)
 id:=foreign.sec.clientID
 hello:=controlBody(helloClient,id,[16]byte{},foreign.sec.clientPublic)
 hello=append(hello,foreign.sec.macPSK(hello)...)
 for i:=0;i<4;i++ {
  _,_ = foreign.ReceiveSecureControl(hello,now.Add(time.Duration(i)*time.Second))
 }
 if !foreign.SecureReady(){t.Fatal("recorded hello must never disconnect existing session")}
 for i:=0;i<20;i++ {
  frame,e:=iran.Encrypt([]byte("flow"));if e!=nil{t.Fatal(e)}
  if _,e=foreign.Decrypt(frame);e!=nil{t.Fatal("authenticated flow stopped under replay",e)}
 }
}
