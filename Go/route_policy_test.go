package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

// Local clock is passed explicitly so demand/fallback behavior is
// deterministic under CI without waiting 90 seconds on wall time.
func routeTestPair(t *testing.T, mode ICMPDirection, start time.Time)(*reverseTransport,*reverseTransport){
    t.Helper()
    key:=bytes.Repeat([]byte{0x4d},32)
    iran,err:=newReverseTransport(mode,key,start)
    if err!=nil{t.Fatal(err)}
    foreign,err:=newReverseTransport(mode,key,start)
    if err!=nil{t.Fatal(err)}
    return iran,foreign
}

func TestRoutePolicyFourConfigurations(t *testing.T) {
    start:=time.Unix(1901000000,0)
    for _,tc:=range []struct{mode ICMPDirection;initial ICMPDirection;canPoll bool}{
        {ICMPAuto,ICMPReverse,true},
        {ICMPAutoDirect,ICMPDirect,true},
        {ICMPReverse,ICMPReverse,true},
        {ICMPDirect,ICMPDirect,false},
    }{
        parsed,err:=ParseICMPDirection(string(tc.mode))
        if err!=nil||parsed!=tc.mode{t.Fatalf("parse %q: %v",tc.mode,err)}
        iran,foreign:=routeTestPair(t,tc.mode,start)
        if got:=iran.direction();got!=tc.initial{t.Fatalf("%s starts %s",tc.mode,got)}
        if got:=foreign.needsProbe(start,true);got!=tc.canPoll{
            t.Fatalf("%s needsProbe=%t expected %t",tc.mode,got,tc.canPoll)
        }
    }
    for _,v:=range []string{"manual","auto_reverse","random",""} {
        if _,err:=ParseICMPDirection(v);err==nil{t.Fatalf("accepted invalid %q",v)}
    }
}

func TestManualRoutesNeverSwitchEvenOnDemandAndSignedProofs(t *testing.T) {
    start:=time.Unix(1901001000,0)
    reverse,_:=routeTestPair(t,ICMPReverse,start)
    direct,_:=routeTestPair(t,ICMPDirect,start)
    for i:=0;i<180;i++ {
        now:=start.Add(time.Duration(i)*time.Second)
        reverse.noteDemand(now,true)
        direct.noteDemand(now,true)
        if reverse.fallbackDirect(now,false,time.Time{}) {t.Fatal("manual reverse auto-fallback")}
        if reverse.choose(ICMPDirect,now) || reverse.rotateKeepingSession(ICMPDirect,now,"unauthorized"){
            t.Fatal("manual reverse changed to direct")
        }
        if direct.choose(ICMPReverse,now) || direct.rotateKeepingSession(ICMPReverse,now,"unauthorized"){
            t.Fatal("manual direct changed to reverse")
        }
        if direct.takeSwitchRequest(now,true)||reverse.takeDirectSwitchRequest(now){
            t.Fatal("manual route sent automatic switch request")
        }
    }
}

func TestDirectFirstFallbackRequiresTwoDemandProofsAndStaleAEAD(t *testing.T) {
    start:=time.Unix(1901002000,0)
    iran,foreign:=routeTestPair(t,ICMPAutoDirect,start)
    t1:=start.Add(91*time.Second)
    for _,now:=range []time.Time{t1,t1.Add(10*time.Second)} {
        iran.noteDemand(now,true)
        probe,err:=foreign.makeProbe(now);if err!=nil{t.Fatal(err)}
        seq:=int(now.Sub(start)/time.Second)+10
        foreign.stageProbe(0x42a5,seq,probe,now)
        if ok,_:=iran.authenticateProbeWithSwitch(probe,now);!ok{t.Fatal("signed PTR4 failed")}
        if !iran.allowDirectPathProof(now){t.Fatal("Iran rejected safe PRF4 reply")}
        proof:=iran.makeProof(probe,now)
        if !bytes.Equal(proof[:4],reverseFallbackProofMagic[:]){t.Fatal("actual local demand not reported")}
        if !foreign.acceptProof(0x42a5,seq,proof,now){t.Fatal("matched PRF4 not accepted")}
    }
    at:=t1.Add(11*time.Second)
    if foreign.takeSwitchRequest(at,false) {t.Fatal("healthy Direct switched despite demand proofs")}
    if !foreign.takeSwitchRequest(at,true) {t.Fatal("stale Direct + two signed local demand proofs did not enable fallback")}
    if foreign.direction()!=ICMPDirect{t.Fatal("Foreign switched before signed handoff ACK")}
    switchFrame,err:=foreign.makeSwitchProbe(at);if err!=nil{t.Fatal(err)}
    foreign.stageReverseSwitch(0x42a5,800,switchFrame,at)
    valid,switchIntent:=iran.authenticateProbeWithSwitch(switchFrame,at)
    if !valid||!switchIntent {t.Fatal("Iran did not authenticate PTS4")}
    if !iran.rotateKeepingSession(ICMPReverse,at,"direct_unavailable") {t.Fatal("Iran fallback refused")}
    ack:=iran.makeSwitchAck(switchFrame,reverseSwitchAckMagic)
    if !foreign.acceptReverseSwitchProof(0x42a5,800,ack,at) ||
       !foreign.rotateKeepingSession(ICMPReverse,at,"direct_unavailable"){
        t.Fatal("Foreign did not verify PTX/ACK or switch to Reverse")
    }
    if foreign.direction()!=ICMPReverse||iran.direction()!=ICMPReverse {t.Fatal("peer route mismatch")}
}

func TestDirectFirstRejectsIdleAndForgedFallbackProof(t *testing.T) {
    start:=time.Unix(1901003000,0)
    iran,foreign:=routeTestPair(t,ICMPAutoDirect,start)
    now:=start.Add(100*time.Second)
    probe,err:=foreign.makeProbe(now);if err!=nil{t.Fatal(err)}
    foreign.stageProbe(0x42a5,1,probe,now)
    reply:=iran.makeProof(probe,now)
    if !bytes.Equal(reply[:4],reverseProofMagic[:]){t.Fatal("idle Iran lied about demand")}
    forged:=bytes.Clone(reply)
    copy(forged[:4],reverseFallbackProofMagic[:])
    if foreign.acceptProof(0x42a5,1,forged,now){t.Fatal("forged demand proof accepted")}
    if !foreign.acceptProof(0x42a5,1,reply,now){t.Fatal("legitimate idle PRA4 rejected")}
    if foreign.takeSwitchRequest(now.Add(time.Second),true){t.Fatal("idle Direct triggered Reverse fallback")}
    if iran.takeDirectSwitchRequest(now){t.Fatal("Direct mode attempted Direct handoff")}
}

func TestDirectFirstReturnUsesMatchedPTX4PTB4(t *testing.T) {
    start:=time.Unix(1901004000,0)
    iran,foreign:=routeTestPair(t,ICMPAutoDirect,start)
    at:=start.Add(100*time.Second)
    if !iran.rotateKeepingSession(ICMPReverse,at,"test_fallback") ||
       !foreign.rotateKeepingSession(ICMPReverse,at,"test_fallback"){
        t.Fatal("cannot enter emergency Reverse state")
    }
    t1:=at.Add(61*time.Second)
    for i,when:=range []time.Time{t1,t1.Add(10*time.Second)}{
        if !iran.shouldProbeDirect(when,true){t.Fatal("missing Direct verification probe")}
        p,err:=iran.makeDirectProbe(when);if err!=nil{t.Fatal(err)}
        iran.stageDirectProbe(0x1188,100+i,p,when)
        if !foreign.authenticateDirectProbe(p,when){t.Fatal("PTC4 HMAC rejected")}
        proof:=foreign.makeDirectProof(p)
        if !iran.acceptDirectProof(0x1188,100+i,proof,when){t.Fatal("PTC4/PDA4 reply not matched")}
    }
    when:=t1.Add(11*time.Second)
    if !iran.takeDirectSwitchRequest(when){t.Fatal("two valid Direct proofs did not enable return")}
    switchFrame,err:=iran.makeDirectSwitchProbe(when);if err!=nil{t.Fatal(err)}
    iran.stageDirectSwitch(0x1188,445,switchFrame,when)
    if !foreign.authenticateDirectSwitchProbe(switchFrame,when) {t.Fatal("PTX4 HMAC rejected")}
    selected,ok:=foreign.allowSignedDirectTakeover()
    if !ok||selected!=ICMPReverse{t.Fatal("Foreign unauthorized direct takeover")}
    ack:=foreign.makeSwitchAck(switchFrame,directSwitchAckMagic)
    fake:=bytes.Clone(ack);fake[len(fake)-1]^=0x10
    if iran.acceptDirectSwitchProof(0x1188,445,fake,when){t.Fatal("forged direct ACK accepted")}
    if !foreign.rotateKeepingSession(ICMPDirect,when,"preferred_direct_recovered"){t.Fatal("Foreign did not switch")}
    if !iran.acceptDirectSwitchProof(0x1188,445,ack,when) ||
       !iran.rotateKeepingSession(ICMPDirect,when,"preferred_direct_recovered") {
        t.Fatal("Iran did not switch on exact PTB4 HMAC reply")
    }
    if iran.direction()!=ICMPDirect||foreign.direction()!=ICMPDirect{t.Fatal("Direct return mismatched")}
    if got:=iran.diagnostics(when).PreferredReverseReturns;got!=1{t.Fatalf("preferred Direct returns %d",got)}
    if iran.takeDirectSwitchRequest(when.Add(time.Second)){t.Fatal("return retried after matched ACK")}
}

func TestDirectFirstHandoffReplaysAndCooldown(t *testing.T) {
    now:=time.Unix(1901005000,0)
    iran,_:=routeTestPair(t,ICMPAutoDirect,now)
    _=iran.rotateKeepingSession(ICMPReverse,now.Add(100*time.Second),"outage")
    at:=now.Add(170*time.Second)
    iran.mu.Lock()
    iran.directProofConfirmations=2
    iran.lastDirectProof=at
    iran.mu.Unlock()
    if !iran.takeDirectSwitchRequest(at){t.Fatal("first PTX4 not staged")}
    if iran.takeDirectSwitchRequest(at.Add(time.Second)){t.Fatal("too-fast retry")}
    if !iran.takeDirectSwitchRequest(at.Add(2*time.Second)){t.Fatal("missing 2s retry")}
    if iran.takeDirectSwitchRequest(at.Add(31*time.Second)){t.Fatal("retry window exceeded")}
    if iran.takeDirectSwitchRequest(at.Add(32*time.Second)){t.Fatal("stale proof bypassed cooldown")}
}

func TestQueueHintKeepsUndeliveredGameFrameWarmWithoutOldSnapshot(t *testing.T) {
    now:=time.Unix(1901006000,0)
    _,foreign:=routeTestPair(t,ICMPAuto,now)
    foreign.mu.Lock()
    foreign.queueHintAt=now
    foreign.queueHintDepth=1
    foreign.queueHintBytes=200
    foreign.queueHintAgeMs=100
    foreign.lastAcceptedWake=now
    foreign.backlogPollUntil=now.Add(reverseWakeBurst)
    foreign.mu.Unlock()
    if got:=foreign.pollPeriod(now.Add(2*time.Second),0,true);got!=25*time.Millisecond{
        t.Fatalf("pending real game data fell to idle too soon: %s",got)
    }
    stale:=foreign.diagnostics(now.Add(2*time.Second))
    if stale.QueueHintDepth!=0||stale.QueueHintBytes!=0||stale.QueueHintAgeMs!=0 ||
       stale.QueueHintAgeSinceReceivedMs!=2000 {
        t.Fatalf("stale queue reported as live: %+v",stale)
    }
    if got:=foreign.pollPeriod(now.Add(7*time.Second),0,true);got!=time.Second{
        t.Fatalf("bounded demand window failed to expire: %s",got)
    }
    foreign.noteUsefulFrame(now.Add(200*time.Millisecond))
    if foreign.queueHintDepth!=0||foreign.queueHintBytes!=0 {
        t.Fatal("delivered packet left misleading byte count")
    }
}
