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
 if r.fallbackDirect(now.Add(370*time.Second),true,now.Add(365*time.Second)){
    t.Fatal("recent genuine peer AEAD traffic did not protect healthy Reverse")
 }
 // A signed poll is one-way evidence, never a substitute for successful
 // ciphertext delivery. A fully stale Reverse session must fail over.
 if !r.fallbackDirect(now.Add(371*time.Second),true,now.Add(216*time.Second)){
    t.Fatal("one-way polls incorrectly blocked Direct recovery")
 }
}

func TestReverseOneWaySignedPollsDoNotSuppressFallbackUnderDemand(t *testing.T) {
    start:=time.Unix(1840000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x36},32),start)
    // ICMP Echo REQUEST arrives and its HMAC validates every second, but
    // none of the Iranian encrypted Echo REPLIES reach the foreign peer.
    for sec:=1;sec<=160;sec++ {
        now:=start.Add(time.Duration(sec)*time.Second)
        r.noteDemand(now,true)
        r.lastValidProbe=now
        if sec < 150 && r.fallbackDirect(now,true,start){
            t.Fatalf("flapped to Direct before full 150s grace at %ds",sec)
        }
    }
    at:=start.Add(160*time.Second)
    if !r.fallbackDirect(at,true,start) {
        t.Fatal("valid one-way polls concealed a dead authenticated return path")
    }
    if r.direction()!=ICMPDirect {t.Fatal("no Direct fallback")}
    if r.lastFallbackReason!="no_authenticated_reverse_feedback" {
        t.Fatalf("unexpected reason %q",r.lastFallbackReason)
    }
    if r.choose(ICMPReverse,at.Add(20*time.Second)){
        t.Fatal("switching back bypassed minimum dwell period")
    }
}
func TestReverseOneWaySignedPollsRemainPreferredWithoutLocalDemand(t *testing.T) {
    start:=time.Unix(1840001000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x37},32),start)
    for hr:=1;hr<=36;hr++ {
        now:=start.Add(time.Duration(hr)*time.Hour)
        r.noteDemand(now,false)
        r.lastValidProbe=now
        if r.fallbackDirect(now,true,start){
            t.Fatalf("idle link unexpectedly switched at hour %d",hr)
        }
    }
    if r.direction()!=ICMPReverse {t.Fatal("quiet Reverse should remain preferred")}
}

func TestReverseModeParsing(t *testing.T){
    for _,mode:=range []string{"auto","direct","reverse"}{
        if _,err:=ParseICMPDirection(mode);err!=nil{t.Fatal(err)}
    }
    if _,err:=ParseICMPDirection("opaque");err==nil{t.Fatal("unrecognized mode accepted")}
}

func TestReverseAutoNeverFailsOverWhileIdleOrPollsHealthy(t *testing.T) {
    start:=time.Unix(1805000000,0)
    key:=bytes.Repeat([]byte{19},32)
    r,_:=newReverseTransport(ICMPAuto,key,start)
    for i:=1;i<=24;i++{
        // A quiet reverse link may be idle for hours; it is not failed.
        now:=start.Add(time.Duration(i)*time.Hour)
        r.noteDemand(now,false)
        if r.fallbackDirect(now,true,start) {
            t.Fatalf("quiet established reverse failed over at hour %d",i)
        }
    }
    // Long-lived flow with recent authenticated peer DATA and signed polls:
    // the Reverse path is healthy and must stay primary.
    baseline:=start.Add(25*time.Hour)
    for i:=0;i<=190;i++{
        now:=baseline.Add(time.Duration(i)*time.Second)
        r.noteDemand(now,true)
        if i%5==0 {r.lastValidProbe=now}
        if r.fallbackDirect(now,true,now.Add(-3*time.Second)){
            t.Fatalf("healthy authenticated Reverse path flipped at second %d",i)
        }
    }
    if r.direction()!=ICMPReverse {t.Fatal("preferred reverse changed unexpectedly")}
    d:=r.diagnostics(baseline.Add(190*time.Second))
    if d.FallbackCount!=0||d.FallbackReason!="" {
        t.Fatalf("unexpected failover diagnostics: %+v",d)
    }
}

func TestReverseAutoRejectsShortDemandAndIntermittentProbeLoss(t *testing.T) {
    start:=time.Unix(1805000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{21},32),start)
    for i:=1;i<240;i++{
        now:=start.Add(time.Duration(i)*time.Second)
        if i%15<4 {r.noteDemand(now,true)} else {r.noteDemand(now,false)}
        if i%60==0 {r.lastValidProbe=now}
        if r.fallbackDirect(now,true,start){
            t.Fatalf("intermittent request/packet loss flipped at second %d",i)
        }
    }
}

func TestReverseReplayWindowAcceptsFiveHundredPollsPerSecond(t *testing.T) {
    start:=time.Unix(1835000000,0)
    key:=bytes.Repeat([]byte{0x34},32)
    sender,_:=newReverseTransport(ICMPAuto,key,start)
    receiver,_:=newReverseTransport(ICMPAuto,key,start)
    const polls=10000
    var mostRecent []byte
    for i:=0;i<polls;i++{
        now:=start.Add(time.Duration(i)*2*time.Millisecond)
        probe,err:=sender.makeProbe(now)
        if err!=nil{t.Fatal(err)}
        if !receiver.authenticateProbe(probe,now){
            t.Fatalf("valid probe %d/%d denied after %s; replay capacity must cover the 20s window",
                i,polls,now.Sub(start))
        }
        mostRecent=probe
    }
    if receiver.authenticateProbe(mostRecent,start.Add(19999*time.Millisecond)){
        t.Fatal("duplicate nonce replay passed after sustained high-frequency polling")
    }
    d:=receiver.diagnostics(start.Add(20*time.Second))
    if d.ReplayCapacityRejects!=0 {
        t.Fatalf("legitimate peak stream hit capacity limit: %+v",d)
    }
    // Clearing only expired entries must bound memory even as the endpoint
    // continues to poll after the replay window moves forward.
    for i:=polls;i<polls+1000;i++{
        now:=start.Add(time.Duration(i)*2*time.Millisecond)
        probe,err:=sender.makeProbe(now)
        if err!=nil || !receiver.authenticateProbe(probe,now){
            t.Fatalf("fresh poll %d denied after replay window advanced: %v",i,err)
        }
    }
    if n:=len(receiver.recent);n>reverseReplayCacheLimit {
        t.Fatalf("nonce cache not bounded: %d",n)
    }
}

func TestReverseReplayCacheCapacityRejectsAreVisible(t *testing.T) {
    now:=time.Unix(1835000000,0)
    key:=bytes.Repeat([]byte{0x56},32)
    sender,_:=newReverseTransport(ICMPAuto,key,now)
    receiver,_:=newReverseTransport(ICMPAuto,key,now)
    receiver.recent=make(map[[8]byte]time.Time,reverseReplayCacheLimit)
    // Simulate a maliciously high burst that fills the bounded table.
    for i:=0;i<reverseReplayCacheLimit;i++{
        var nonce [8]byte
        nonce[0]=byte(i)
        nonce[1]=byte(i>>8)
        receiver.recent[nonce]=now
    }
    probe,err:=sender.makeProbe(now)
    if err!=nil{t.Fatal(err)}
    if receiver.authenticateProbe(probe,now){
        t.Fatal("full replay table must not silently bypass replay protection")
    }
    if d:=receiver.diagnostics(now);d.ReplayCapacityRejects!=1{
        t.Fatalf("capacity rejection not surfaced: %+v",d)
    }
    if receiver.authenticateProbe(probe,now){
        t.Fatal("probe accepted during unchanged full replay window")
    }
    if d:=receiver.diagnostics(now);d.ReplayCapacityRejects!=2{
        t.Fatalf("rejection count is inconsistent: %+v",d)
    }
}

func TestScheduledReverseProofAuthenticatesBidirectionalPath(t *testing.T){
    start:=time.Unix(1850000000,0)
    key:=bytes.Repeat([]byte{0x41},32)
    foreign,_:=newReverseTransport(ICMPAuto,key,start)
    iran,_:=newReverseTransport(ICMPAuto,key,start)
    switched:=start.Add(100*time.Second)
    if !foreign.choose(ICMPDirect,switched)||!iran.choose(ICMPDirect,switched){t.Fatal("setup Direct")}
    if !foreign.needsProbe(switched,true){t.Fatal("healthy Direct disabled periodic Reverse probes")}
    for i:=0;i<2;i++ {
        now:=switched.Add(time.Duration(10+i*10)*time.Second)
        probe,err:=foreign.makeProbe(now);if err!=nil{t.Fatal(err)}
        id,seq:=0x42a5,20+i
        foreign.stageProbe(id,seq,probe,now)
        valid,sw:=iran.authenticateProbeWithSwitch(probe,now)
        if !valid||sw{t.Fatal("valid ordinary probe rejected or upgraded to switch")}
        if !iran.allowDirectPathProof(now){t.Fatal("sparse Direct health proof denied")}
        proof:=iran.makeProof(probe)
        forged:=bytes.Clone(proof);forged[len(forged)-1]^=1
        if foreign.acceptProof(id,seq,forged,now){t.Fatal("forged path proof accepted")}
        if foreign.acceptProof(id,seq+1,proof,now){t.Fatal("unmatched ICMP sequence proof accepted")}
        if !foreign.acceptProof(id,seq,proof,now.Add(50*time.Millisecond)){
            t.Fatal("fresh paired return-path proof rejected")
        }
        if foreign.acceptProof(id,seq,proof,now.Add(100*time.Millisecond)){
            t.Fatal("replayed proof accepted")
        }
    }
    if foreign.takeSwitchRequest(switched.Add(30*time.Second)){
        t.Fatal("Reverse takeover ignored minimum 60-second Direct dwell")
    }
    now:=switched.Add(65*time.Second)
    // The last proof has expired: demand two recent observations.
    if foreign.takeSwitchRequest(now){t.Fatal("stale proofs initiated takeover")}
    for i:=0;i<2;i++ {
        moment:=now.Add(time.Duration(i*10)*time.Second)
        probe,_:=foreign.makeProbe(moment)
        id,seq:=0x42a5,50+i
        foreign.stageProbe(id,seq,probe,moment)
        valid,_:=iran.authenticateProbeWithSwitch(probe,moment);if !valid{t.Fatal("new valid probe")}
        proof:=iran.makeProof(probe)
        if !foreign.acceptProof(id,seq,proof,moment){t.Fatal("proof refused")}
    }
    at:=now.Add(11*time.Second)
    if !foreign.takeSwitchRequest(at){t.Fatal("no scheduled preferred Reverse switch")}
    if foreign.takeSwitchRequest(at.Add(time.Second)){t.Fatal("duplicate switch without proof")}
    switchProbe,err:=foreign.makeSwitchProbe(at);if err!=nil{t.Fatal(err)}
    valid,sw:=iran.authenticateProbeWithSwitch(switchProbe,at)
    if !valid||!sw{t.Fatal("valid signed switch probe rejected")}
    if iran.authenticateProbe(switchProbe,at){t.Fatal("replayed switch accepted")}
    if !iran.choose(ICMPReverse,at){t.Fatal("Reverse priority not restored")}
}
func TestFailedOrStaleReverseProbesNeverInterruptDirect(t *testing.T){
    start:=time.Unix(1850001000,0)
    key:=bytes.Repeat([]byte{0x42},32)
    foreign,_:=newReverseTransport(ICMPAuto,key,start)
    iran,_:=newReverseTransport(ICMPAuto,key,start)
    at:=start.Add(80*time.Second)
    if !foreign.choose(ICMPDirect,at)||!iran.choose(ICMPDirect,at){t.Fatal("setup Direct")}
    for n:=1;n<=1000;n++{
        now:=at.Add(time.Duration(n)*time.Second)
        // Signed request arrival at Iran proves only Foreign -> Iran.
        p,_:=foreign.makeProbe(now)
        if !iran.authenticateProbe(p,now){t.Fatal("signed probe rejected")}
        if foreign.takeSwitchRequest(now){t.Fatal("one-way probes took over live Direct")}
    }
    if foreign.direction()!=ICMPDirect||iran.direction()!=ICMPDirect{
        t.Fatal("one-way health checks changed direction")
    }
}

func TestScheduledDirectProbeDoesNotDisturbHealthyPriorityReverse(t *testing.T) {
    start:=time.Unix(1855000000,0)
    key:=bytes.Repeat([]byte{0x61},32)
    iran,_:=newReverseTransport(ICMPAuto,key,start)
    foreign,_:=newReverseTransport(ICMPAuto,key,start)
    if iran.shouldProbeDirect(start,false){t.Fatal("pre-handshake Direct probe sent")}
    if !iran.shouldProbeDirect(start,true){t.Fatal("healthy Reverse did not schedule Direct check")}
    if iran.shouldProbeDirect(start.Add(30*time.Second),true){t.Fatal("Direct check exceeded 1/minute")}
    probe,e:=iran.makeDirectProbe(start);if e!=nil{t.Fatal(e)}
    id,seq:=0x42a6,42
    iran.stageDirectProbe(id,seq,probe,start)
    if !foreign.authenticateDirectProbe(probe,start){t.Fatal("HMACed Direct probe rejected")}
    proof:=foreign.makeDirectProof(probe)
    forged:=bytes.Clone(proof);forged[29]^=0x01
    if iran.acceptDirectProof(id,seq,forged,start){t.Fatal("forged Direct proof accepted")}
    if iran.acceptDirectProof(id,seq+1,proof,start){t.Fatal("unmatched Direct proof accepted")}
    if !iran.acceptDirectProof(id,seq,proof,start.Add(80*time.Millisecond)){
        t.Fatal("paired Direct return path proof rejected")
    }
    if iran.acceptDirectProof(id,seq,proof,start.Add(time.Second)){
        t.Fatal("Direct proof replay accepted")
    }
    if iran.direction()!=ICMPReverse || foreign.direction()!=ICMPReverse {
        t.Fatal("background Direct check switched away from healthy Reverse")
    }
    d:=iran.diagnostics(start.Add(time.Second))
    if d.DirectProbeChecks!=1||d.DirectPathProofs!=1||
        d.DirectLastProofAgeSeconds!=0 {
        t.Fatalf("Direct check telemetry wrong: %+v",d)
    }
    if !iran.shouldProbeDirect(start.Add(60*time.Second),true){t.Fatal("Direct check not periodic")}
    if !iran.choose(ICMPDirect,start.Add(130*time.Second)){t.Fatal("setup Direct")}
    if iran.shouldProbeDirect(start.Add(190*time.Second),true){
        t.Fatal("Direct health check ran as synthetic traffic on Direct")
    }
}
