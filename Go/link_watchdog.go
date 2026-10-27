package pingtunnel

import "time"

// peerRecoveryWatchdog escalates prolonged missing ICMP replies to systemd
// only when the local peer actively needs the tunnel. Normal idle and short
// network outages must never trigger restart loops.
type peerRecoveryWatchdog struct {
    noPongSince time.Time
}

func (w *peerRecoveryWatchdog) shouldRestart(now, lastPong, lastDemand time.Time, activeFlows bool) bool {
    demand := activeFlows || (!lastDemand.IsZero() && now.Sub(lastDemand) < 30*time.Second)
    if !demand || lastPong.IsZero() || now.Before(lastPong) ||
        now.Sub(lastPong) <= 90*time.Second {
        w.noPongSince = time.Time{}
        return false
    }
    if w.noPongSince.IsZero() {
        w.noPongSince = now
        return false
    }
    return now.Sub(w.noPongSince) >= 4*time.Minute
}
