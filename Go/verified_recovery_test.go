package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

// Reproduce the real 1Hz client health loop across an impaired 65s session.
// Only TWO independent root-MACed Direct roundtrips and continuous user
// demand with stale authenticated peer traffic enable fast fallback.
func TestVerifiedDirectBackupSpeedsRecoveryWithoutIdleSwitch(t *testing.T) {
    started := time.Unix(1901100000,0)
    iran, foreign := routeTestPair(t,ICMPAuto,started)
    proofs := 0
    for sec:=0;sec<=61;sec++ {
        now:=started.Add(time.Duration(sec)*time.Second)
        iran.noteDemand(now,true)
        ready:=sec<35 // secure watchdog is permitted to rekey at 35s
        if iran.shouldProbeDirect(now,ready,started) {
            probe,err:=iran.makeDirectProbe(now)
            if err!=nil {t.Fatal(err)}
            seq:=100+sec
            iran.stageDirectProbe(42,seq,probe,now)
            if !foreign.authenticateDirectProbe(probe,now) {t.Fatal("peer Direct test failed authentication")}
            ack:=foreign.makeDirectProof(probe)
            if !iran.acceptDirectProof(42,seq,ack,now) {t.Fatal("Direct reply failed matched proof")}
            proofs++
        }
        if sec<60 && iran.fallbackDirect(now,ready,started) {
            t.Fatalf("premature fallback at %d seconds",sec)
        }
    }
    if proofs<2 {t.Fatalf("only %d verified Direct proofs",proofs)}
    if !iran.fallbackDirect(started.Add(61*time.Second),false,started) {
        t.Fatal("confirmed Direct backup did not recover a 60s stalled Reverse")
    }
    if iran.direction()!=ICMPDirect {t.Fatal("failed to select the verified backup")}
}

func TestVerifiedDirectBackupRejectsMissingProofOrDemand(t *testing.T) {
    started:=time.Unix(1901200000,0)
    iran,_:=routeTestPair(t,ICMPAuto,started)
    for sec:=0;sec<=61;sec++ {
        iran.noteDemand(started.Add(time.Duration(sec)*time.Second),true)
    }
    now:=started.Add(61*time.Second)
    if iran.fallbackDirect(now,false,started) {
        t.Fatal("stalled Reverse without alternate authenticated proof switched early")
    }
    idle,_:=routeTestPair(t,ICMPAuto,started)
    if idle.shouldProbeDirect(now,false,started) {
        t.Fatal("idle link started accelerated backup probing")
    }
    // Tampering with a signed Direct proof cannot synthesize evidence.
    probe,err:=iran.makeDirectProbe(now)
    if err!=nil {t.Fatal(err)}
    iran.stageDirectProbe(42,1,probe,now)
    forged:=bytes.Clone(probe)
    copy(forged[:4],directProofMagic[:])
    if iran.acceptDirectProof(42,1,forged,now) {
        t.Fatal("untrusted Direct proof accepted")
    }
}
