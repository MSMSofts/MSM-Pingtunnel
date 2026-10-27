package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

// Cover the actual production scheduler peak: 500 authenticated polls/s over
// a 20-second replay window. A previous 4096-entry limit would reject good
// packets after around eight seconds of sustained activity.
func TestReverseSignedPollsAtPeakRateDoNotExhaustReplayCache(t *testing.T) {
    start:=time.Unix(1810000000,0)
    key:=bytes.Repeat([]byte{0x43},32)
    foreign,_:=newReverseTransport(ICMPReverse,key,start)
    iran,_:=newReverseTransport(ICMPReverse,key,start)
    var replay []byte
    for i:=0;i<10000;i++ {
        now:=start.Add(time.Duration(i)*2*time.Millisecond)
        p,err:=foreign.makeProbe(now)
        if err!=nil{t.Fatal(err)}
        if !iran.authenticateProbe(p,now){
            t.Fatalf("legitimate poll rejected at %d (%.1fs)",i,now.Sub(start).Seconds())
        }
        if i==100 {replay=append([]byte(nil),p...)}
        if i==101 && iran.authenticateProbe(replay,now) {
            t.Fatal("replayed valid signed poll accepted")
        }
    }
    d:=iran.diagnostics(start.Add(20*time.Second))
    if d.ProbeCacheOverflows!=0 {
        t.Fatalf("high-rate healthy polls exceeded cache: %+v",d)
    }
    if d.ProbeReplayEntries>reverseReplayLimit || d.ProbeReplayEntries<=4096 {
        t.Fatalf("cache capacity incorrectly sized: %+v",d)
    }
    later:=start.Add(45*time.Second)
    p,err:=foreign.makeProbe(later)
    if err!=nil || !iran.authenticateProbe(p,later) {
        t.Fatalf("legitimate signed poll did not recover after window expiry: %v",err)
    }
    if got:=iran.diagnostics(later).ProbeReplayEntries;got>=5000 {
        t.Fatalf("old replay nonces were not pruned: %d",got)
    }
}
