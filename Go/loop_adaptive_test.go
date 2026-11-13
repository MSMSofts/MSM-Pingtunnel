package pingtunnel

import (
    "testing"
    "time"
)

func TestUpstreamAdaptiveLoopTimerReuseAndBounds(t *testing.T) {
    w:=newAdaptiveLoopWait(2*time.Millisecond,80*time.Millisecond)
    defer w.stop()
    if w.t!=nil {t.Fatal("lazy timer created before first wait")}
    if w.miss()!=2*time.Millisecond || w.miss()!=4*time.Millisecond {
        t.Fatal("idle ramp no longer starts at the original latency floor")
    }
    for i:=0;i<30;i++{w.miss()}
    if w.miss()!=80*time.Millisecond {
        t.Fatal("idle loop exceeded configured wait cap")
    }
    w.hit()
    if w.miss()!=2*time.Millisecond {
        t.Fatal("application activity failed to restore fast polling")
    }
    first:=w.arm(2*time.Millisecond)
    original:=w.t
    select {
    case <-first:
    case <-time.After(200*time.Millisecond):
        t.Fatal("reusable idle timer did not expire")
    }
    second:=w.arm(3*time.Millisecond)
    if w.t!=original || second!=first {
        t.Fatal("arming another delay allocated a new timer or channel")
    }
    select {
    case <-second:
    case <-time.After(200*time.Millisecond):
        t.Fatal("rearmed timer did not fire")
    }
}

func TestUpstreamAdaptiveLoopStopAndRearm(t *testing.T) {
    w:=newAdaptiveLoopWait(0,0)
    if w.min!=time.Millisecond || w.max!=time.Millisecond {
        t.Fatal("invalid min/max were not clamped")
    }
    _=w.arm(25*time.Millisecond)
    w.stop()
    if w.t!=nil {t.Fatal("timer retained on TCP loop completion")}
    select {
    case <-w.arm(time.Millisecond):
    case <-time.After(200*time.Millisecond):
        t.Fatal("stopped timer could not be safely rearmed")
    }
    w.stop()
}
