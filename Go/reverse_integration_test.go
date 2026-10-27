package pingtunnel

import (
 "bytes"
 "net"
 "testing"
 "time"

 "golang.org/x/net/icmp"
 "golang.org/x/net/ipv4"
)

// Verify a full authenticated four-message handshake and bidirectional
// ciphertext flow carried by the intended ICMP Echo types and matched IDs.
// This exercises the real wire encoders, handshake and AEAD, without assuming
// that a local test machine allows raw network sockets.
func TestReverseICMPEchoHandshakeAndEncryptedData(t *testing.T) {
 now:=time.Now()
 key:=pairedTestKey(t)
 iran,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 foreign,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 if err=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
 if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
 if err=iran.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
 if err=foreign.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
 if err=iran.BindSecurePeer("203.0.113.5");err!=nil{t.Fatal(err)}
 if err=foreign.BindSecurePeer("203.0.113.4");err!=nil{t.Fatal(err)}
 if !useReverse(iran)||!useReverse(foreign){t.Fatal("auto must begin reverse on both physical regions")}
 wrap:=func(typ,id,seq int,body []byte)[]byte{
  w,err:=(&icmp.Message{Type:ipv4.ICMPType(typ),Code:0,Body:&icmp.Echo{ID:id,Seq:seq,Data:body}}).Marshal(nil)
  if err!=nil{t.Fatal(err)}
  return w
 }
 unwrap:=func(w []byte,typ,id,seq int)[]byte{
  msg,err:=icmp.ParseMessage(1,w)
  if err!=nil{t.Fatal(err)}
  if int(msg.Type.(ipv4.ICMPType))!=typ {t.Fatalf("incorrect ICMP type %v, want %d",msg.Type,typ)}
  echo,ok:=msg.Body.(*icmp.Echo)
  if !ok||echo.ID!=id||echo.Seq!=seq{t.Fatal("response ID or sequence did not match request")}
  return echo.Data
 }
 // Foreign sends an authenticated Echo Request, Iran answers with a
 // ClientHello inside the same request's Echo Reply.
 probe,err:=foreign.reverse.makeProbe(now)
 if err!=nil{t.Fatal(err)}
 if !iran.reverse.authenticateProbe(unwrap(wrap(8,431,1,probe),8,431,1),now){t.Fatal("foreign probe invalid")}
 h1,err:=iran.SecureControl(now)
 if err!=nil||len(h1)==0{t.Fatalf("missing reverse Hello: %v",err)}
 reply1:=wrap(0,431,1,h1)
 serverHello,err:=foreign.ReceiveSecureControl(unwrap(reply1,0,431,1),now)
 if err!=nil||len(serverHello)==0{t.Fatalf("reverse server hello: %v",err)}
 finish,err:=iran.ReceiveSecureControl(unwrap(wrap(8,431,2,serverHello),8,431,2),now)
 if err!=nil||len(finish)==0{t.Fatalf("reverse client finish: %v",err)}
 ack,err:=foreign.ReceiveSecureControl(unwrap(wrap(0,431,2,finish),0,431,2),now)
 if err!=nil||len(ack)==0{t.Fatalf("reverse server ack: %v",err)}
 last,err:=iran.ReceiveSecureControl(unwrap(wrap(8,431,3,ack),8,431,3),now)
 if err!=nil||len(last)!=0{t.Fatalf("reverse final confirmation: %v",err)}
 if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("reverse path did not authenticate")}
 // Repeated authenticated polling must leave an established key intact.
 nextProbe,err:=foreign.reverse.makeProbe(now.Add(time.Second))
 if err!=nil||!iran.reverse.authenticateProbe(nextProbe,now.Add(time.Second)){t.Fatal("post-handshake poll refused")}
 if !iran.reverse.allowReverseCandidate(now.Add(time.Second),true,iran.sec.lastPeerTraffic()) {
  t.Fatal("established reverse connection no longer accepts polls")
 }
 if !iran.SecureReady(){t.Fatal("healthy poll reset session")}
 // Iran's queued app data goes in Echo Reply; foreign's app data in Echo Request.
 outbound,err:=iran.Encrypt([]byte("Iran forwarded payload"))
 if err!=nil{t.Fatal(err)}
 if !iran.reverse.enqueue(outbound,now){t.Fatal("queue refused encrypted data")}
 out:=iran.reverse.take(now.Add(time.Millisecond))
 plain,err:=foreign.Decrypt(unwrap(wrap(0,431,4,out),0,431,4))
 if err!=nil||string(plain)!="Iran forwarded payload"{t.Fatalf("reverse data invalid: %v",err)}
 back,err:=foreign.Encrypt([]byte("Foreign response payload"))
 if err!=nil{t.Fatal(err)}
 plain,err=iran.Decrypt(unwrap(wrap(8,431,5,back),8,431,5))
 if err!=nil||string(plain)!="Foreign response payload"{t.Fatalf("reverse response invalid: %v",err)}
 if _,err=foreign.Decrypt(out);err==nil{t.Fatal("accepted replayed reverse application packet")}
 if foreign.SecureStats().ReplayDrops==0{t.Fatal("replay protection not recorded")}
 _=net.IPv4(203,0,113,4) // transport peers remain pinned by BindSecurePeer
 if bytes.Equal(out,back){t.Fatal("bidirectional ciphertext unexpectedly identical")}
}

func TestReverseUnavailableFallsBackToDirectHandshake(t *testing.T) {
 now:=time.Now()
 key:=pairedTestKey(t)
 iran,_:=NewCryptoConfig(AUTO,key)
 foreign,_:=NewCryptoConfig(AUTO,key)
 if err:=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
 if err:=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
 if err:=iran.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
 if err:=foreign.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
 // No reverse poll is received. Local timeout switches to direct.
 if !iran.reverse.fallbackDirect(now.Add(26*time.Second),false,time.Time{}){t.Fatal("did not attempt direct fallback")}
 if useReverse(iran){t.Fatal("fallback did not select direct")}
 h1,err:=iran.SecureControl(now)
 if err!=nil{t.Fatal(err)}
 h2,err:=foreign.ReceiveSecureControl(h1,now)
 if err!=nil{t.Fatal(err)}
 if !foreign.reverse.choose(ICMPDirect,now.Add(26*time.Second)){t.Fatal("foreign did not accept direct hello")}
 h3,err:=iran.ReceiveSecureControl(h2,now)
 if err!=nil{t.Fatal(err)}
 h4,err:=foreign.ReceiveSecureControl(h3,now)
 if err!=nil{t.Fatal(err)}
 if _,err=iran.ReceiveSecureControl(h4,now);err!=nil{t.Fatal(err)}
 if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("direct fallback handshake failed")}
}
