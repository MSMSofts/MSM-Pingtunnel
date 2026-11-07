package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

func queueAwareTransportPair(t *testing.T,start time.Time)(*reverseTransport,*reverseTransport){
    t.Helper()
    key:=bytes.Repeat([]byte{0x62},32)
    iran,err:=newReverseTransport(ICMPAuto,key,start)
    if err!=nil {t.Fatal(err)}
    foreign,err:=newReverseTransport(ICMPAuto,key,start)
    if err!=nil {t.Fatal(err)}
    return iran,foreign
}

func TestQueueAwarePollingUsesActualAuthenticatedBacklog(t *testing.T){
    start:=time.Unix(1900000000,0)
    iran,foreign:=queueAwareTransportPair(t,start)
    if p:=foreign.pollPeriod(start,0,true);p!=time.Second {
        t.Fatalf("idle unhinted poll=%s",p)
    }
    if !iran.enqueue([]byte("game-packet"),start){t.Fatal("enqueue")}
    hint,err:=iran.makeQueueHint(start)
    if err!=nil||len(hint)!=reverseQueueHintBytes{t.Fatalf("hint length/error: %d %v",len(hint),err)}
    if hint[0]!='P'||hint[1]!='T'||hint[2]!='Q'||hint[3]!='4' {t.Fatal("hint magic")}
    if !foreign.authenticateQueueHint(hint,start) {t.Fatal("authenticated queue hint rejected")}
    if !foreign.noteAuthenticatedBacklogWake(start){t.Fatal("missed poller wake")}
    if p:=foreign.pollPeriod(start.Add(10*time.Millisecond),0,true);p!=8*time.Millisecond {
        t.Fatalf("new game datagram should get immediate 8ms burst, got %s",p)
    }
    if p:=foreign.pollPeriod(start.Add(200*time.Millisecond),0,true);p!=16*time.Millisecond {
        t.Fatalf("single game packet should decay to measured 16ms, got %s",p)
    }
    if foreign.authenticateQueueHint(hint,start.Add(100*time.Millisecond)) {
        t.Fatal("replayed queue demand was accepted")
    }
    for i:=0;i<24;i++ {
        if !iran.enqueue([]byte("burst"),start.Add(500*time.Millisecond)){t.Fatal("enqueue burst")}
    }
    newHint,err:=iran.makeQueueHint(start.Add(500*time.Millisecond));if err!=nil{t.Fatal(err)}
    if !foreign.authenticateQueueHint(newHint,start.Add(500*time.Millisecond)){t.Fatal("growing queue hint rejected")}
    if !foreign.noteAuthenticatedBacklogWake(start.Add(500*time.Millisecond)){t.Fatal("valid wake throttled")}
    if p:=foreign.pollPeriod(start.Add(510*time.Millisecond),0,true);p!=8*time.Millisecond{
        t.Fatalf("queue pressure should briefly accelerate to <=125/s, got %s",p)
    }
    diag:=foreign.diagnostics(start.Add(510*time.Millisecond))
    if diag.QueueHintsReceived!=2||diag.QueueHintDepth!=25||diag.QueueHintAgeMs!=500 {
        t.Fatalf("queue hint diagnostics wrong: %+v",diag)
    }
    if p:=foreign.pollPeriod(start.Add(2*time.Second),0,true);p!=time.Second {
        t.Fatalf("stale hint should return to 1Hz, got %s",p)
    }
}

func TestQueueHintRejectsForgeryReplayAndImpossibleMeasurements(t *testing.T){
    start:=time.Unix(1900001000,0)
    iran,foreign:=queueAwareTransportPair(t,start)
    if !iran.enqueue([]byte("real-data"),start){t.Fatal("enqueue")}
    frame,err:=iran.makeQueueHint(start);if err!=nil{t.Fatal(err)}
    evil:=bytes.Clone(frame);evil[22]^=0x40
    if foreign.authenticateQueueHint(evil,start){t.Fatal("unsigned queue age forged")}
    evil=bytes.Clone(frame);evil[20]^=0x01
    if foreign.authenticateQueueHint(evil,start){t.Fatal("unsigned queue depth forged")}
    evil=bytes.Clone(frame);evil[29]^=0x04
    if foreign.authenticateQueueHint(evil,start){t.Fatal("forged HMAC accepted")}
    if foreign.authenticateQueueHint(frame,start.Add(21*time.Second)){t.Fatal("stale hint accepted")}
    if !foreign.authenticateQueueHint(frame,start){t.Fatal("valid hint rejected")}
    if foreign.authenticateQueueHint(frame,start){t.Fatal("hint replay accepted")}
    if len(foreign.queueHintSeen)!=1{t.Fatal("forged hints filled replay map")}
    if foreign.choose(ICMPDirect,start.Add(100*time.Second))!=true{t.Fatal("test direct fallback")}
    nextFrame,err:=iran.makeQueueHint(start.Add(101*time.Second));if err!=nil{t.Fatal(err)}
    if foreign.authenticateQueueHint(nextFrame,start.Add(101*time.Second)){
        t.Fatal("direct route accepted foreign reverse backlog acceleration")
    }
}

func TestQueueHintNeverChangesRouteOrKeys(t *testing.T){
    start:=time.Unix(1900002000,0)
    iran,foreign:=queueAwareTransportPair(t,start)
    if !iran.enqueue([]byte("ciphertext"),start){t.Fatal("enqueue")}
    hint,err:=iran.makeQueueHint(start);if err!=nil{t.Fatal(err)}
    if !foreign.authenticateQueueHint(hint,start){t.Fatal("hint authentication")}
    if !foreign.noteAuthenticatedBacklogWake(start){t.Fatal("wake")}
    if foreign.direction()!=ICMPReverse||iran.direction()!=ICMPReverse{
        t.Fatal("queue observation switched path")
    }
    if foreign.takeSwitchRequest(start.Add(time.Minute)){
        t.Fatal("queue hint counted as two-way Reverse handoff proof")
    }
    if foreign.diagnostics(start).ReverseProofs!=0 {t.Fatal("queue telemetry forged a route proof")}
}

func TestQueueHintRejectsRapidDuplicateReportsAndBoundsMemory(t *testing.T) {
    start:=time.Unix(1900003000,0)
    iran,foreign:=queueAwareTransportPair(t,start)
    _=iran.enqueue([]byte("live"),start)
    for i:=0;i<100;i++ {
        at:=start.Add(time.Duration(i)*250*time.Millisecond)
        hint,err:=iran.makeQueueHint(at)
        if err!=nil{t.Fatal(err)}
        accepted:=foreign.authenticateQueueHint(hint,at)
        if i%2==0 && !accepted{t.Fatalf("valid 500ms-spaced hint rejected: %d",i)}
        if i%2==1 && accepted{t.Fatalf("250ms hint exceeded rate ceiling: %d",i)}
        if n:=len(foreign.queueHintSeen);n>reverseQueueHintSeenLimit{
            t.Fatalf("queue hint replay memory exceeded limit: %d",n)
        }
    }
    if foreign.queueHintRejected<50{t.Fatal("fast reports not counted")}
}

func TestQueueHintRateBoundsAndZeroBacklog(t *testing.T) {
    if reverseQueueHintPollInterval(0,0)!=time.Second {t.Fatal("zero backlog should not accelerate")}
    for _,tc:=range []struct{depth,age int;want time.Duration}{
        {1,0,16*time.Millisecond},{2,0,12*time.Millisecond},
        {1,20,12*time.Millisecond},{6,0,10*time.Millisecond},
        {1,40,10*time.Millisecond},{16,0,8*time.Millisecond},
        {1,80,8*time.Millisecond},{256,12000,8*time.Millisecond},
    }{
        if p:=reverseQueueHintPollInterval(tc.depth,tc.age);p!=tc.want {
            t.Fatalf("depth=%d age=%d actual=%s want=%s",tc.depth,tc.age,p,tc.want)
        }
    }
    start:=time.Unix(1900004000,0)
    iran,foreign:=queueAwareTransportPair(t,start)
    hint,err:=iran.makeQueueHint(start)
    if err!=nil||hint!=nil{t.Fatal("empty queue generated unsolicited wake")}
    // The older 36-byte PTW4 protocol stays valid for staged upgrades.
    wake,err:=iran.makeBacklogWake(start);if err!=nil{t.Fatal(err)}
    if !foreign.authenticateBacklogWake(wake,start){t.Fatal("legacy PTW4 rejected")}
    if !foreign.noteAuthenticatedBacklogWake(start){t.Fatal("legacy wake note")}
    if p:=foreign.pollPeriod(start.Add(time.Millisecond),0,true);p!=reverseFastPollPeriod{
        t.Fatalf("legacy wake cadence changed: %s",p)
    }
}

func BenchmarkQueueAwarePollSelection(b *testing.B) {
    start:=time.Unix(1900005000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x65},32),start)
    r.queueHintAt=start
    r.queueHintDepth=6
    r.queueHintAgeMs=40
    r.backlogPollUntil=start.Add(reverseWakeBurst)
    r.lastAcceptedWake=start
    b.ReportAllocs()
    for i:=0;i<b.N;i++ {
        r.pollPeriod(start.Add(400*time.Millisecond),1,true)
    }
}
