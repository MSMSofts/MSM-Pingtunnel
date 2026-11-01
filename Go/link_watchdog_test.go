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

func TestIdleClientDoesNotInventDemandOrRunHotPings(t *testing.T) {
    var c Client
    if !c.lastActivity().IsZero() {
        t.Fatal("never-active client must not synthesize local user demand")
    }
    now:=time.Now()
    if got:=c.nextPingInterval(now);got!=10*time.Second {
        t.Fatalf("idle ICMP ping cadence must be cold, got %s",got)
    }
    var w peerRecoveryWatchdog
    oldPong:=now.Add(-10*time.Minute)
    if w.shouldRestart(now,oldPong,c.lastActivity(),false) ||
      w.shouldRestart(now.Add(10*time.Minute),oldPong,c.lastActivity(),false) {
        t.Fatal("idle client cannot trigger the Direct link restart watchdog")
    }
    c.touchActivity()
    if c.lastActivity().IsZero() {
        t.Fatal("real application activity was not recorded")
    }
    if got:=c.nextPingInterval(time.Now());got!=time.Second {
        t.Fatalf("active ICMP ping cadence must be hot, got %s",got)
    }
}
