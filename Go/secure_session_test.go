package pingtunnel

import (
 "bytes"
 "crypto/rand"
 "errors"
 "net"
 "testing"
 "time"
)

func newSecurePair(t *testing.T)(*CryptoConfig,*CryptoConfig){
 t.Helper()
 key:=pairedTestKey(t)
 a,e:=NewCryptoConfig(AUTO,key);if e!=nil{t.Fatal(e)}
 b,e:=NewCryptoConfig(AUTO,key);if e!=nil{t.Fatal(e)}
 establishEphemeralPair(t,a,b)
 return a,b
}

func TestReplayWindowExactDuplicateAndOutOfOrder(t *testing.T){
 a,b:=newSecurePair(t)
 var frames [][]byte
 for i:=0;i<1100;i++{
  f,e:=a.Encrypt([]byte{byte(i)})
  if e!=nil{t.Fatal(e)}
  frames=append(frames,f)
 }
 if out,e:=b.Decrypt(frames[1099]);e!=nil||out[0]!=byte(1099%256){t.Fatalf("newest invalid: %v",e)}
 if _,e:=b.Decrypt(frames[1099]);e==nil{t.Fatal("identical ciphertext was replayed")}
 if _,e:=b.Decrypt(frames[1097]);e!=nil{t.Fatal("out of order fresh packet rejected: ",e)}
 if _,e:=b.Decrypt(frames[1097]);e==nil{t.Fatal("out-of-order duplicate accepted")}
 if _,e:=b.Decrypt(frames[0]);e==nil{t.Fatal("out-of-window replay accepted")}
 if _,e:=b.Decrypt(frames[1098]);e!=nil{t.Fatal("legitimate reordered packet rejected: ",e)}
 if b.SecureStats().ReplayDrops<3{t.Fatal("replay counter not updated")}
}

func TestInvalidTagAndTamperedCountersNeverConsumeReplayWindow(t *testing.T){
 a,b:=newSecurePair(t)
 frame,e:=a.Encrypt([]byte("authenticated"))
 if e!=nil{t.Fatal(e)}
 for _,pos:=range []int{4,5,21,len(frame)-1}{
  modified:=bytes.Clone(frame)
  modified[pos]^=0x40
  if _,e=b.Decrypt(modified);e==nil{t.Fatalf("accepted modified packet byte %d",pos)}
 }
 original,e:=b.Decrypt(frame)
 if e!=nil||string(original)!="authenticated"{t.Fatal("failed to open legitimate frame after tamper")}
 if _,e=b.Decrypt(frame);e==nil{t.Fatal("duplicate accepted")}
}

func TestEphemeralHandshakeAuthenticationAndFailClosedV3(t *testing.T){
 key:=pairedTestKey(t)
 iran,_:=NewCryptoConfig(AUTO,key)
 foreign,_:=NewCryptoConfig(AUTO,key)
 if e:=iran.BindRegion("iran");e!=nil{t.Fatal(e)}
 if e:=foreign.BindRegion("foreign");e!=nil{t.Fatal(e)}
 _=iran.BindSecurePeer("203.0.113.5")
 _=foreign.BindSecurePeer("203.0.113.4")
 if _,e:=iran.Encrypt([]byte("user secrets"));!errors.Is(e,ErrSecureNegotiation){
  t.Fatal("plaintext sent before key agreement")
 }
 h1,_:=iran.SecureControl(time.Now())
 wrong:=bytes.Clone(h1);wrong[len(wrong)-1]^=0x10
 if _,e:=foreign.ReceiveSecureControl(wrong,time.Now());e==nil{t.Fatal("forged client hello accepted")}
 h2,e:=foreign.ReceiveSecureControl(h1,time.Now())
 if e!=nil{t.Fatal(e)}
 badH2:=bytes.Clone(h2);badH2[40]^=0x02
 if _,e=iran.ReceiveSecureControl(badH2,time.Now());e==nil{t.Fatal("forged server hello accepted")}
 h3,e:=iran.ReceiveSecureControl(h2,time.Now())
 if e!=nil{t.Fatal(e)}
 badH3:=bytes.Clone(h3);badH3[len(badH3)-1]^=0x1
 if _,e=foreign.ReceiveSecureControl(badH3,time.Now());e==nil{t.Fatal("invalid X25519 confirmation accepted")}
 h4,e:=foreign.ReceiveSecureControl(h3,time.Now())
 if e!=nil{t.Fatal(e)}
 if _,e=iran.ReceiveSecureControl(h4,time.Now());e!=nil{t.Fatal(e)}
 old,_:=NewCryptoConfig(AUTO,key)
 if e=old.BindRegion("iran");e!=nil{t.Fatal(e)}
 if old.sec==nil{t.Fatal("no mandatory ephemeral mode")}
 // This frame from the old v3 static-key scheme must be refused.
 oldFrame,e:=old.auto.encrypt([]byte("legacy static-key data"))
 if e!=nil{t.Fatal(e)}
 if _,e=foreign.Decrypt(oldFrame);e==nil{t.Fatal("v3 static-key downgrade accepted")}
}

func TestForwardSecrecyNewHandshakeChangesCiphertextKey(t *testing.T){
 a,b:=newSecurePair(t)
 first,e:=a.Encrypt([]byte("same plaintext"));if e!=nil{t.Fatal(e)}
 if _,e=b.Decrypt(first);e!=nil{t.Fatal(e)}
 // Simulate Iran service recovery and a fresh ECDH on the same paired root.
 now:=time.Now().Add(90*time.Second)
 if !a.sec.recoverIfStale(now,true){t.Fatal("expected authenticated rekey on long outage")}
 if a.SecureReady(){t.Fatal("must gate traffic before rekey handshake")}
 // Server idle timeout permits a new authenticated client hello.
 h1,e:=a.SecureControl(now);if e!=nil{t.Fatal(e)}
 h2,e:=b.ReceiveSecureControl(h1,now);if e!=nil||len(h2)==0{t.Fatalf("new server hello: %v",e)}
 h3,e:=a.ReceiveSecureControl(h2,now);if e!=nil{t.Fatal(e)}
 h4,e:=b.ReceiveSecureControl(h3,now);if e!=nil{t.Fatal(e)}
 if _,e=a.ReceiveSecureControl(h4,now);e!=nil{t.Fatal(e)}
 fresh,e:=a.Encrypt([]byte("same plaintext"));if e!=nil{t.Fatal(e)}
 if bytes.Equal(first,fresh){t.Fatal("ephemeral rekey reused session frame")}
 if _,e=b.Decrypt(first);e==nil{t.Fatal("old session ciphertext accepted in new session")}
 if plain,e:=b.Decrypt(fresh);e!=nil||string(plain)!="same plaintext"{t.Fatalf("new session failed: %v",e)}
}

func TestHandshakeLossIdempotencyAndRecovery(t *testing.T){
 a,b:=newSecurePair(t)
 now:=time.Now().Add(90*time.Second)
 if !a.sec.recoverIfStale(now,true){t.Fatal("could not trigger recovery")}
 if _,e:=a.Encrypt([]byte("data"));!errors.Is(e,ErrSecureNegotiation){t.Fatal("fail-open")}
 hello,_:=a.SecureControl(now)
 serverHello,e:=b.ReceiveSecureControl(hello,now)
 if e!=nil{t.Fatal(e)}
 duplicate,e:=b.ReceiveSecureControl(hello,now.Add(time.Second))
 if e!=nil||!bytes.Equal(serverHello,duplicate){t.Fatal("repeated hello must return same signed server key")}
 finish,e:=a.ReceiveSecureControl(serverHello,now)
 if e!=nil{t.Fatal(e)}
 ack,e:=b.ReceiveSecureControl(finish,now)
 if e!=nil{t.Fatal(e)}
 ack2,e:=b.ReceiveSecureControl(finish,now.Add(time.Second))
 if e!=nil||!bytes.Equal(ack,ack2){t.Fatal("lost final ACK must be safely replayable")}
 if _,e=a.ReceiveSecureControl(ack,now);e!=nil{t.Fatal(e)}
 if !a.SecureReady()||!b.SecureReady(){t.Fatal("recovery handshake incomplete")}
}

func TestSecurePeerIdentityRestrictsSpoofing(t *testing.T){
 a,_:=newSecurePair(t)
 if !a.SecurePeerAllowed(net.ParseIP("203.0.113.5")){t.Fatal("configured peer rejected")}
 if a.SecurePeerAllowed(net.ParseIP("203.0.113.6")){t.Fatal("unknown remote IP accepted")}
 var garbage [32]byte
 if _,e:=rand.Read(garbage[:]);e!=nil{t.Fatal(e)}
 if _,e:=a.Decrypt(garbage[:]);e==nil{t.Fatal("unsigned data accepted")}
}
