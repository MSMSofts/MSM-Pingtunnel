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
    if r.fallbackDirect(now.Add(20*time.Second),false,time.Time{}){t.Fatal("direct selected before reverse startup deadline")}
    if !r.fallbackDirect(now.Add(26*time.Second),false,time.Time{}){t.Fatal("auto did not fall back to direct on reverse timeout")}
    if r.choose(ICMPReverse,now.Add(45*time.Second)){t.Fatal("switch hysteresis not enforced")}
    if !r.choose(ICMPReverse,now.Add(87*time.Second)){t.Fatal("auto could not retry reverse after cooldown")}
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
 r.noteDemand(now.Add(40*time.Second),true)
 if !r.fallbackDirect(now.Add(41*time.Second),false,time.Time{}){t.Fatal("startup did not fall back after timeout")}
 if r.allowReverseCandidate(now.Add(60*time.Second),false,time.Time{}){t.Fatal("direct stabilization cooldown was bypassed")}
 if !r.allowReverseCandidate(now.Add(102*time.Second),false,time.Time{}){t.Fatal("reverse retry blocked after cooldown")}
 if !r.choose(ICMPReverse,now.Add(102*time.Second)){t.Fatal("could not retry reverse")}
 r.noteDemand(now.Add(210*time.Second),true)
 if r.fallbackDirect(now.Add(210*time.Second),true,now.Add(190*time.Second)){t.Fatal("fresh reverse traffic triggered fallback")}
 if !r.fallbackDirect(now.Add(213*time.Second),true,now.Add(110*time.Second)){t.Fatal("stale reverse link did not fall back")}
}

func TestReverseModeParsing(t *testing.T){
    for _,mode:=range []string{"auto","direct","reverse"}{
        if _,err:=ParseICMPDirection(mode);err!=nil{t.Fatal(err)}
    }
    if _,err:=ParseICMPDirection("opaque");err==nil{t.Fatal("unrecognized mode accepted")}
}
