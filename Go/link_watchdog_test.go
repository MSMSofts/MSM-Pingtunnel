package pingtunnel

import (
    "testing"
    "time"
)

func TestPeerRecoveryWatchdogRespectsIdleAndHysteresis(t *testing.T) {
    start := time.Unix(1000000, 0)
    var w peerRecoveryWatchdog
    oldPong := start.Add(-2 * time.Minute)
    if w.shouldRestart(start, oldPong, start.Add(-time.Hour), false) {
        t.Fatal("idle core must not be restarted")
    }
    if w.shouldRestart(start, oldPong, start, true) {
        t.Fatal("first lost pong must not immediately restart")
    }
    if w.shouldRestart(start.Add(3*time.Minute), oldPong, start, true) {
        t.Fatal("short demand outage must not restart")
    }
    if !w.shouldRestart(start.Add(4*time.Minute), oldPong, start, true) {
        t.Fatal("sustained demand with no pong must restart")
    }
}
func TestPeerRecoveryWatchdogRecoversAndResets(t *testing.T) {
    start:=time.Unix(2000000,0)
    var w peerRecoveryWatchdog
    w.shouldRestart(start, start.Add(-2*time.Minute), start, true)
    if w.shouldRestart(start.Add(2*time.Minute),start.Add(2*time.Minute),start,true) {
        t.Fatal("fresh pong must clear watchdog")
    }
    if w.shouldRestart(start.Add(4*time.Minute), start.Add(-time.Minute), start, true) {
        t.Fatal("freshly lost pong must restart a new window")
    }
    if w.shouldRestart(start.Add(9*time.Minute), start.Add(-time.Minute), start.Add(-time.Hour), false) {
        t.Fatal("absence of demand must reset watchdog")
    }
}
