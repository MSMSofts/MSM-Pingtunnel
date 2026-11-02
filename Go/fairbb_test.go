package pingtunnel

import "testing"

// A full interval without ACKs must not permanently pin the flow's
// in-flight counter above the congestion window.
func TestBBRecoveryAfterEntireAckIntervalLost(t *testing.T) {
    bb := newBBControl()
    bb.Init()
    for i := 0; i < 18; i++ {
        if !bb.CanSend(i, 65536) {
            t.Fatalf("unexpected early backpressure at send %d", i)
        }
    }
    if bb.flyingdata <= bb.maxfly {
        t.Fatal("test must create more bytes in flight than the window")
    }
    if bb.CanSend(20, 65536) {
        t.Fatal("expected backpressure before recovery")
    }
    bb.Update() // the entire feedback interval was lost
    if bb.flyingdata != 0 {
        t.Fatalf("in-flight bytes remained pinned: %d", bb.flyingdata)
    }
    if bb.maxfly < bbLostFloor {
        t.Fatalf("lost interval reduced the window below probe floor: %d", bb.maxfly)
    }
    if !bb.CanSend(21, 65536) {
        t.Fatal("lost ACK interval permanently stalled new transmissions")
    }
}

func TestBBHealthyAckIntervalRetainsSendBudget(t *testing.T) {
    bb := newBBControl()
    bb.Init()
    if !bb.CanSend(1, 888) {
        t.Fatal("initial frame unexpectedly blocked")
    }
    bb.RecvAck(1, 888)
    bb.Update()
    if bb.maxfly < bbMaxflyFloor {
        t.Fatalf("healthy interval unexpectedly shrank window: %d", bb.maxfly)
    }
    if !bb.CanSend(2, 888) {
        t.Fatal("healthy flow cannot send subsequent frame")
    }
}
