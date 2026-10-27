package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

func TestReverseProbeAuthenticatedAndReplaySafe(t *testing.T){
    now:=time.Unix(1800000000,0)
    one,err:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{3},32),now)
    if err!=nil{t.Fatal(err)}
    peer,err:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{3},32),now)
    if err!=nil{t.Fatal(err)}
    probe,err:=one.makeProbe(now)
    if err!=nil{t.Fatal(err)}
    if !peer.authenticateProbe(probe,now){t.Fatal("valid probe was rejected")}
    if peer.authenticateProbe(probe,now){t.Fatal("replayed probe was accepted")}
    forged:=bytes.Clone(probe);forged[26]^=0x10
    if peer.authenticateProbe(forged,now){t.Fatal("forged probe was accepted")}
    other,err:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{4},32),now)
    if err!=nil{t.Fatal(err)}
    if other.authenticateProbe(probe,now){t.Fatal("wrong shared key accepted")}
    if one.authenticateProbe(probe,now.Add(time.Minute)){t.Fatal("stale probe accepted")}
}

func TestReverseSelectionAndAutomaticGracePeriod(t *testing.T){
    now:=time.Unix(1800000000,0)
    key:=bytes.Repeat([]byte{7},32)
    r,err:=newReverseTransport(ICMPAuto,key,now)
    if err!=nil{t.Fatal(err)}
    if r.direction()!=ICMPReverse{t.Fatal("auto did not choose reverse on startup")}
    if !r.needsProbe(now,true){t.Fatal("auto did not probe reverse immediately")}
    r.noteDemand(now.Add(time.Second),true)
    if r.fallbackDirect(now.Add(26*time.Second),false,time.Time{}){t.Fatal("a short handshake delay switched to direct")}
    if r.fallbackDirect(now.Add(90*time.Second),false,time.Time{}){t.Fatal("demand must remain sustained")}
    // Constant real traffic with no reverse requests justifies fallback.
    for elapsed:=2;elapsed<=94;elapsed++{
        r.noteDemand(now.Add(time.Duration(elapsed)*time.Second),true)
    }
    if !r.fallbackDirect(now.Add(94*time.Second),false,time.Time{}){t.Fatal("unreachable reverse did not fall back after sustained demand")}
    if r.choose(ICMPReverse,now.Add(105*time.Second)){t.Fatal("switch hysteresis not enforced")}
    if !r.choose(ICMPReverse,now.Add(155*time.Second)){t.Fatal("auto could not retry reverse after cooldown")}
    d,_:=newReverseTransport(ICMPDirect,key,now)
    if d.needsProbe(now.Add(time.Hour),false) || d.choose(ICMPReverse,now.Add(time.Hour)){t.Fatal("direct-only mode changed direction")}
    only,_:=newReverseTransport(ICMPReverse,key,now)
    if only.direction()!=ICMPReverse || only.choose(ICMPDirect,now.Add(time.Minute)){t.Fatal("reverse-only mode changed direction")}
}

func TestReverseQueueBoundsAndTTL(t *testing.T){
    now:=time.Unix(1800000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{8},32),now)
    a:=[]byte("one")
    if !r.enqueue(a,now){t.Fatal("enqueue failed")}
    a[0]='X'
    if out:=r.take(now.Add(time.Second));string(out)!="one"{t.Fatalf("queue aliasing or ordering: %q",out)}
    for i:=0;i<300;i++{if !r.enqueue([]byte{byte(i)},now){t.Fatal("queue refused frame")}}
    n,drops:=r.statistics()
    if n!=256||drops!=44{t.Fatalf("queue not bounded n=%d dropped=%d",n,drops)}
    if f:=r.take(now.Add(20*time.Second));len(f)!=0{t.Fatal("expired frame emitted")}
    n,drops=r.statistics()
    if n!=0 || drops!=300{t.Fatalf("expiration accounting mismatch n=%d dropped=%d",n,drops)}
    if r.enqueue(make([]byte,10241),now){t.Fatal("oversized frame accepted")}
}

func TestAutoReverseRequiresTrafficAndStaleAuthentication(t *testing.T){
 now:=time.Unix(1800000000,0)
 r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{9},32),now)
 if !r.allowReverseCandidate(now,false,time.Time{}){t.Fatal("initial reverse candidate unavailable")}
 for i:=1;i<=110;i++{r.noteDemand(now.Add(time.Duration(i)*time.Second),true)}
 // A recent paired poll proves the reverse request path is alive even
 // when X25519 needs multiple attempts, so no premature fallback.
 r.lastValidProbe=now.Add(100*time.Second)
 if r.fallbackDirect(now.Add(110*time.Second),false,time.Time{}) {
    t.Fatal("valid incoming Reverse polls did not protect negotiation")
 }
 for i:=111;i<=151;i++{r.noteDemand(now.Add(time.Duration(i)*time.Second),true)}
 if !r.fallbackDirect(now.Add(151*time.Second),false,time.Time{}) {
    t.Fatal("persistently unconfirmed reverse handshake did not eventually fail over")
 }
 if r.allowReverseCandidate(now.Add(180*time.Second),false,time.Time{}){t.Fatal("direct stabilization cooldown was bypassed")}
 if !r.allowReverseCandidate(now.Add(215*time.Second),false,time.Time{}){t.Fatal("reverse retry blocked after cooldown")}
 if !r.choose(ICMPReverse,now.Add(215*time.Second)){t.Fatal("could not retry reverse")}
 for i:=216;i<=370;i++{r.noteDemand(now.Add(time.Duration(i)*time.Second),true)}
 r.lastValidProbe=now.Add(369*time.Second)
 if r.fallbackDirect(now.Add(370*time.Second),true,now.Add(216*time.Second)){
    t.Fatal("recent reverse polls did not protect healthy but idle AEAD session")
 }
 r.lastValidProbe=now.Add(216*time.Second)
 if !r.fallbackDirect(now.Add(371*time.Second),true,now.Add(216*time.Second)){
    t.Fatal("fully stale authenticated reverse failed to enter emergency direct")
 }
}

func TestReverseModeParsing(t *testing.T){
    for _,mode:=range []string{"auto","direct","reverse"}{
        if _,err:=ParseICMPDirection(mode);err!=nil{t.Fatal(err)}
    }
    if _,err:=ParseICMPDirection("opaque");err==nil{t.Fatal("unrecognized mode accepted")}
}
