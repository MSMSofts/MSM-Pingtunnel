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
 // No authenticated Reverse poll is received, and the local client
 // continuously needs transport service for longer than the failover grace.
 for i:=1;i<=95;i++{
   iran.reverse.noteDemand(now.Add(time.Duration(i)*time.Second),true)
 }
 if iran.reverse.fallbackDirect(now.Add(26*time.Second),false,time.Time{}){
   t.Fatal("initial reverse handshake was preempted by a short timeout")
 }
 if !iran.reverse.fallbackDirect(now.Add(95*time.Second),false,time.Time{}){
   t.Fatal("sustained reverse outage did not attempt direct fallback")
 }
 if useReverse(iran){t.Fatal("fallback did not select direct")}
 h1,err:=iran.SecureControl(now)
 if err!=nil{t.Fatal(err)}
 h2,err:=foreign.ReceiveSecureControl(h1,now)
 if err!=nil{t.Fatal(err)}
 if !foreign.reverse.choose(ICMPDirect,now.Add(95*time.Second)){t.Fatal("foreign did not accept direct hello")}
 h3,err:=iran.ReceiveSecureControl(h2,now)
 if err!=nil{t.Fatal(err)}
 h4,err:=foreign.ReceiveSecureControl(h3,now)
 if err!=nil{t.Fatal(err)}
 if _,err=iran.ReceiveSecureControl(h4,now);err!=nil{t.Fatal(err)}
 if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("direct fallback handshake failed")}
}


// Simulate a real asymmetric outage: signed Foreign->Iran Reverse polls
// continue arriving, but encrypted Iran->Foreign Echo Replies are lost.
// The authenticated path must fail over to Direct, then (if Direct later
// becomes unhealthy and Reverse is reachable again) recover in the other
// direction without re-pairing, relaxing AEAD, or restarting either process.
func TestAutoReverseDirectReverseRecoveryWithAuthenticatedHandshakes(t *testing.T) {
    start:=time.Now()
    key:=pairedTestKey(t)
    iran,e:=NewCryptoConfig(AUTO,key);if e!=nil{t.Fatal(e)}
    foreign,e:=NewCryptoConfig(AUTO,key);if e!=nil{t.Fatal(e)}
    if e=iran.BindRegion("iran");e!=nil{t.Fatal(e)}
    if e=foreign.BindRegion("foreign");e!=nil{t.Fatal(e)}
    if e=iran.BindICMPDirection("auto");e!=nil{t.Fatal(e)}
    if e=foreign.BindICMPDirection("auto");e!=nil{t.Fatal(e)}
    if e=iran.BindSecurePeer("203.0.113.5");e!=nil{t.Fatal(e)}
    if e=foreign.BindSecurePeer("203.0.113.4");e!=nil{t.Fatal(e)}

    // Complete a Reverse X25519 handshake; both endpoints are authenticated.
    h1,e:=iran.SecureControl(start);if e!=nil{t.Fatal(e)}
    h2,e:=foreign.ReceiveSecureControl(h1,start);if e!=nil{t.Fatal(e)}
    h3,e:=iran.ReceiveSecureControl(h2,start);if e!=nil{t.Fatal(e)}
    h4,e:=foreign.ReceiveSecureControl(h3,start);if e!=nil{t.Fatal(e)}
    if _,e=iran.ReceiveSecureControl(h4,start);e!=nil{t.Fatal(e)}
    if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("initial Reverse not authenticated")}

    // Every second, an authentic Foreign-origin poll reaches Iran. These
    // signed polls prove only the request leg, not return-path delivery.
    for sec:=1;sec<=160;sec++ {
        now:=start.Add(time.Duration(sec)*time.Second)
        iran.reverse.noteDemand(now,true)
        probe,err:=foreign.reverse.makeProbe(now);if err!=nil{t.Fatal(err)}
        if !iran.reverse.authenticateProbe(probe,now){t.Fatal("signed poll rejected")}
        if sec<150 && iran.reverse.fallbackDirect(now,true,start) {
            t.Fatalf("premature Reverse failover at %ds",sec)
        }
    }
    at:=start.Add(161*time.Second)
    if !iran.reverse.fallbackDirect(at,true,start){t.Fatal("one-way Reverse outage blocked Direct recovery")}
    iran.sec.resetForTransportChange()
    if !iran.SecureReady() { // required: old secure session must be invalidated
    } else {t.Fatal("old Iran session survived direction change")}
    if useReverse(iran)==true {t.Fatal("Iran did not select Direct")}

    // A valid Direct ClientHello enters Foreign as an ICMP Echo REQUEST.
    // Foreign selects Direct only after verifying the paired handshake.
    h1,e=iran.SecureControl(at);if e!=nil{t.Fatal(e)}
    h2,e=foreign.ReceiveSecureControl(h1,at);if e!=nil||len(h2)==0{t.Fatalf("Direct hello rejected: %v",e)}
    if !foreign.reverse.choose(ICMPDirect,at){t.Fatal("Foreign did not accept Direct")}
    h3,e=iran.ReceiveSecureControl(h2,at);if e!=nil{t.Fatal(e)}
    h4,e=foreign.ReceiveSecureControl(h3,at);if e!=nil{t.Fatal(e)}
    if _,e=iran.ReceiveSecureControl(h4,at);e!=nil{t.Fatal(e)}
    if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("Direct handshake did not authenticate")}
    directPacket,e:=iran.Encrypt([]byte("direct-payload"));if e!=nil{t.Fatal(e)}
    directPlain,e:=foreign.Decrypt(directPacket)
    if e!=nil||string(directPlain)!="direct-payload"{t.Fatalf("Direct AEAD traffic failed: %v",e)}
    if !iran.reverse.needsProbe(at,true) || !foreign.reverse.needsProbe(at,true) {
        t.Fatal("AUTO must keep checking preferred Reverse even during healthy Direct")
    }
    if !iran.SecureReady() || !foreign.SecureReady() || useReverse(iran) || useReverse(foreign) {
        t.Fatal("mere scheduled probe cannot tear down healthy Direct")
    }
    // Foreign probes on a 10s cadence; Iran verifies each signed request
    // and returns a different signed userspace Echo Reply (PRA4). The
    // challenge nonce, matched ICMP ID/seq and MAC prove both network legs
    // without resetting the established Direct AEAD session.
    back:=start.Add(273*time.Second)
    for i:=0;i<2;i++ {
        moment:=back.Add(time.Duration(-20+i*10)*time.Second)
        probe,e:=foreign.reverse.makeProbe(moment);if e!=nil{t.Fatal(e)}
        id,seq:=17061,100+i
        foreign.reverse.stageProbe(id,seq,probe,moment)
        if !iran.reverse.authenticateProbe(probe,moment){t.Fatal("fresh Reverse probe rejected")}
        if !iran.reverse.allowDirectPathProof(moment){t.Fatal("failed to authorize sparse signed proof")}
        proof:=iran.reverse.makeProof(probe)
        if !foreign.reverse.acceptProof(id,seq,proof,moment.Add(50*time.Millisecond)){
            t.Fatal("paired Reverse return-path proof was rejected")
        }
        if !iran.SecureReady()||!foreign.SecureReady() {
            t.Fatal("path probing destroyed healthy Direct AEAD")
        }
    }
    if !foreign.reverse.takeSwitchRequest(back,true){t.Fatal("emergency Reverse recovery failed after Direct became stale")}
    switchProbe,e:=foreign.reverse.makeSwitchProbe(back);if e!=nil{t.Fatal(e)}
    valid,switchIntent:=iran.reverse.authenticateProbeWithSwitch(switchProbe,back)
    if !valid||!switchIntent{t.Fatal("authenticated PTS4 switch intent rejected")}
    if !iran.reverse.choose(ICMPReverse,back){t.Fatal("Iran failed to return to Reverse after cooldown")}
    iran.sec.resetForTransportChange()

    // Echo Reply ClientHello, Echo Request ServerHello, Echo Reply Finish,
    // Echo Request Ack: same authenticated four-step handshake as startup.
    h1,e=iran.SecureControl(back);if e!=nil{t.Fatal(e)}
    h2,e=foreign.ReceiveSecureControl(h1,back);if e!=nil||len(h2)==0{t.Fatalf("Reverse recovery hello rejected: %v",e)}
    if !foreign.reverse.choose(ICMPReverse,back){t.Fatal("Foreign failed to return to Reverse")}
    h3,e=iran.ReceiveSecureControl(h2,back);if e!=nil{t.Fatal(e)}
    h4,e=foreign.ReceiveSecureControl(h3,back);if e!=nil{t.Fatal(e)}
    if _,e=iran.ReceiveSecureControl(h4,back);e!=nil{t.Fatal(e)}
    if !iran.SecureReady()||!foreign.SecureReady()||!useReverse(iran)||!useReverse(foreign) {
        t.Fatal("automatic Reverse recovery did not authenticate both peers")
    }
    if _,e=foreign.Decrypt(directPacket);e==nil{t.Fatal("old Direct ciphertext accepted after rekey")}
    reversePacket,e:=iran.Encrypt([]byte("reverse-restored"));if e!=nil{t.Fatal(e)}
    reversePlain,e:=foreign.Decrypt(reversePacket)
    if e!=nil||string(reversePlain)!="reverse-restored"{t.Fatalf("new Reverse AEAD session failed: %v",e)}
}
