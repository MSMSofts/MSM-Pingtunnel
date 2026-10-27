package pingtunnel

import (
 "bytes"
 "testing"
 "time"
)

// At the maximum 2-ms reverse scheduler rate the 20-second signed-poll
// freshness window contains ~10,000 distinct valid nonces. The previous
// 4096-entry cap rejected healthy polls during sustained video transfers.
func TestReverseReplayCacheAcceptsTwentySecondsAtPeakPollRate(t *testing.T) {
    start:=time.Unix(1810000000,0)
    key:=bytes.Repeat([]byte{0x63},32)
    foreign,err:=newReverseTransport(ICMPReverse,key,start)
    if err!=nil{t.Fatal(err)}
    iran,err:=newReverseTransport(ICMPReverse,key,start)
    if err!=nil{t.Fatal(err)}
    var first []byte
    for i:=0;i<10000;i++ {
        now:=start.Add(time.Duration(i)*2*time.Millisecond)
        probe,err:=foreign.makeProbe(now)
        if err!=nil{t.Fatal(err)}
        if !iran.authenticateProbe(probe,now){
            t.Fatalf("valid signed Poll rejected at index %d (elapsed %s)",i,now.Sub(start))
        }
        if i==100 {first=append([]byte(nil),probe...)}
        if i==101 && iran.authenticateProbe(first,now) {
            t.Fatal("duplicate signed nonce was accepted")
        }
    }
    diag:=iran.diagnostics(start.Add(20*time.Second))
    if diag.ReplayCapacityRejects!=0 {
        t.Fatalf("legitimate Polls were discarded due to replay cache saturation: %+v",diag)
    }
    if len(iran.recent)<9000 || len(iran.recent)>reverseReplayCacheLimit {
        t.Fatalf("replay cache not bounded correctly: %d",len(iran.recent))
    }
    later:=start.Add(45*time.Second)
    p,err:=foreign.makeProbe(later)
    if err!=nil || !iran.authenticateProbe(p,later){
        t.Fatalf("cache did not recover after expiration: %v",err)
    }
    if len(iran.recent)>100 {
        t.Fatalf("old signed nonces retained well beyond replay window: %d",len(iran.recent))
    }
}
