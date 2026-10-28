package pingtunnel

import (
    "bytes"
    "sync"
    "testing"
    "time"
)

func TestReverseAdaptivePollCadence(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,err:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{15},32),now)
    if err!=nil{t.Fatal(err)}
    if got:=r.pollPeriod(now,0,false);got!=200*time.Millisecond{
        t.Fatalf("negotiation poll interval %s",got)
    }
    if got:=r.pollPeriod(now,0,true);got!=250*time.Millisecond{
        t.Fatalf("idle interval %s",got)
    }
    r.noteUsefulFrame(now)
    if got:=r.pollPeriod(now.Add(50*time.Millisecond),1,true);got!=12*time.Millisecond{
        t.Fatalf("isolated inbound data interval: %s",got)
    }
    r.noteUsefulFrame(now.Add(100*time.Millisecond))
    if got:=r.pollPeriod(now.Add(150*time.Millisecond),1,true);got!=6*time.Millisecond{
        t.Fatalf("warm reverse interval %s",got)
    }
    r.noteUsefulFrame(now.Add(160*time.Millisecond))
    r.noteUsefulFrame(now.Add(200*time.Millisecond))
    if got:=r.pollPeriod(now.Add(250*time.Millisecond),1,true);got!=2*time.Millisecond{
        t.Fatalf("sustained reverse throughput capped at %s",got)
    }
    if got:=r.pollPeriod(now.Add(2*time.Second),1,true);got!=2*time.Millisecond{
        t.Fatalf("sustained return data burst cooled during jitter window: %s",got)
    }
    if got:=r.pollPeriod(now.Add(3*time.Second),1,true);got!=6*time.Millisecond{
        t.Fatalf("reverse burst did not step down to 6ms: %s",got)
    }
    if got:=r.pollPeriod(now.Add(5*time.Second),1,true);got!=25*time.Millisecond {
        t.Fatalf("reverse ACK activity did not cool after bounded hold: %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),1,true);got!=25*time.Millisecond{
        t.Fatalf("open QUIC return path must not wait 80ms: %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),0,true);got!=250*time.Millisecond{
        t.Fatalf("idle reverse interval %s",got)
    }
    d:=r.diagnostics(now.Add(10*time.Second))
    if d.PollIntervalMillis!=250 || d.LastUsefulFrameAgeSeconds!=9{
        t.Fatalf("wrong reverse diagnostic snapshot: %+v",d)
    }
}

func TestReverseFailedWritePreservesFIFOAndOriginalDeadline(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{5},32),now)
    if !r.enqueue([]byte("first"),now) || !r.enqueue([]byte("second"),now.Add(time.Millisecond)){
        t.Fatal("queue could not accept frames")
    }
    sent:=0
    if sendQueuedReverse(r,now.Add(time.Second),func(body []byte)bool{
        sent++
        if string(body)!="first"{t.Fatalf("expected first, got %q",body)}
        return false
    }){t.Fatal("write failure treated as success")}
    d:=r.diagnostics(now.Add(time.Second))
    if d.Pending!=2||d.FailedReplies!=1||d.PendingBytes!=len("first")+len("second"){
        t.Fatalf("failed write silently lost frame: %+v",d)
    }
    if !sendQueuedReverse(r,now.Add(2*time.Second),func(body []byte)bool{
        if string(body)!="first"{t.Fatalf("FIFO lost after retry: %q",body)}
        return true
    }){t.Fatal("retransmission failed")}
    if !sendQueuedReverse(r,now.Add(2*time.Second),func(body []byte)bool{
        if string(body)!="second"{t.Fatalf("second frame misplaced: %q",body)}
        return true
    }){t.Fatal("second frame failed")}
    if sent!=1{t.Fatal("unexpected failed sends")}
    if r.diagnostics(now).Pending!=0{t.Fatal("queue not drained")}
    if !r.enqueue([]byte("expiring"),now){t.Fatal("could not enqueue expiration case")}
    if !sendQueuedReverse(r,now.Add(13*time.Second),func(body []byte)bool{
        t.Fatalf("userspace must not emit an empty poll reply: %q",body)
        return false
    }){t.Fatal("expired frame cleanup failed")}
    if d:=r.diagnostics(now.Add(13*time.Second));d.QueueDrops!=1{
        t.Fatalf("expired frame not counted: %+v",d)
    }
}

func TestReverseTransportQueueConcurrentLoadBounded(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{8},32),now)
    const senders=12
    const frames=450
    var wg sync.WaitGroup
    for i:=0;i<senders;i++{
        wg.Add(1)
        go func(){
            defer wg.Done()
            for j:=0;j<frames;j++{
                if !r.enqueue(bytes.Repeat([]byte{byte(j)},700),now){t.Error("enqueue failure");return}
                _=r.pollPeriod(now.Add(time.Millisecond),1,true)
                _=r.diagnostics(now)
            }
        }()
    }
    wg.Wait()
    d:=r.diagnostics(now)
    if d.Pending>reverseQueueMaxFrames || d.PendingBytes>reverseQueueMaxBytes {
        t.Fatalf("queue exceeded configured memory cap: %+v",d)
    }
    if d.QueueDrops==0 {t.Fatal("overloaded bounded queue did not account for dropped frames")}
}


func TestAuthenticatedReverseReceiptsOnlyForRealData(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{9},32),now)
    if r.shouldSendReceiveAck(now){t.Fatal("idle reverse tunnel sent synthetic receipt")}
    r.noteUsefulFrame(now)
    if !r.shouldSendReceiveAck(now){t.Fatal("valid remote data did not schedule receipt")}
    if r.shouldSendReceiveAck(now.Add(100*time.Millisecond)){
        t.Fatal("receipt loop emitted excessive acknowledgements")
    }
    if !r.shouldSendReceiveAck(now.Add(8*time.Second)){
        t.Fatal("bounded receipt rate was too slow")
    }
    if r.shouldSendReceiveAck(now.Add(20*time.Second)){
        t.Fatal("stale traffic kept producing encrypted receipts")
    }
}

func TestReverseVideoOutboundAcceleratesReturnACKPolling(t *testing.T) {
    start:=time.Unix(1830000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{5},32),start)
    if got:=r.pollPeriod(start,2,true);got!=25*time.Millisecond {
        t.Fatalf("active baseline should be 25ms, got %s",got)
    }
    r.noteOutboundFrame(start)
    if got:=r.pollPeriod(start.Add(100*time.Millisecond),2,true);got!=12*time.Millisecond {
        t.Fatalf("first video response did not accelerate ACK polling: %s",got)
    }
    for n:=1;n<=4;n++ {r.noteOutboundFrame(start.Add(time.Duration(n*30)*time.Millisecond))}
    if got:=r.pollPeriod(start.Add(140*time.Millisecond),2,true);got!=4*time.Millisecond {
        t.Fatalf("sustained video frames should keep ACK polling responsive: %s",got)
    }
    if got:=r.pollPeriod(start.Add(3*time.Second),2,true);got!=4*time.Millisecond {
        t.Fatalf("short video pause must retain warm ACK cadence: %s",got)
    }
    if got:=r.pollPeriod(start.Add(6*time.Second),2,true);got!=12*time.Millisecond {
        t.Fatalf("outbound data must step down to 12ms after sustained burst: %s",got)
    }
    if got:=r.pollPeriod(start.Add(9*time.Second),2,true);got!=25*time.Millisecond {
        t.Fatalf("stale outbound traffic must cool back to 25ms: %s",got)
    }
    if got:=r.pollPeriod(start.Add(10*time.Second),0,true);got!=250*time.Millisecond {
        t.Fatalf("no active application must return to idle: %s",got)
    }
    if got:=r.pollPeriod(start.Add(11*time.Second),0,false);got!=200*time.Millisecond {
        t.Fatalf("handshake traffic must preserve startup pacing: %s",got)
    }
    d:=r.diagnostics(start.Add(10*time.Second))
    if d.LastOutboundDataAgeMs!=9880 {
        t.Fatalf("outbound data age inaccurate: %d",d.LastOutboundDataAgeMs)
    }
}
func TestReverseQueueLatencyMeasuresSuccessfulWritesOnly(t *testing.T) {
    start:=time.Unix(1830000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{13},32),start)
    if !r.enqueue([]byte("first"),start)||!r.enqueue([]byte("second"),start.Add(40*time.Millisecond)){
        t.Fatal("could not queue encrypted frames")
    }
    d:=r.diagnostics(start.Add(200*time.Millisecond))
    if d.OldestQueueAgeMs!=200||d.DeliveredFrames!=0 {
        t.Fatalf("missing true head queue age: %+v",d)
    }
    if sendQueuedReverse(r,start.Add(250*time.Millisecond),func([]byte)bool{return false}){
        t.Fatal("failed socket write returned success")
    }
    if d=r.diagnostics(start.Add(250*time.Millisecond));d.DeliveredFrames!=0||d.OldestQueueAgeMs!=250 {
        t.Fatalf("failed write counted as successful delivery: %+v",d)
    }
    if !sendQueuedReverse(r,start.Add(300*time.Millisecond),func([]byte)bool{return true}){
        t.Fatal("retry failed")
    }
    if !sendQueuedReverse(r,start.Add(310*time.Millisecond),func([]byte)bool{return true}){
        t.Fatal("second delivery failed")
    }
    d=r.diagnostics(start.Add(310*time.Millisecond))
    if d.DeliveredFrames!=2||d.DelayedFrames!=2||d.LastQueueDelayMs!=270||
        d.MaxQueueDelayMs!=300||d.OldestQueueAgeMs!=0 {
        t.Fatalf("queue residence telemetry wrong: %+v",d)
    }
    if !sendQueuedReverse(r,start.Add(330*time.Millisecond),func([]byte)bool{
        t.Fatal("empty poll must not be emitted by userspace")
        return false
    }) {
        t.Fatal("empty queue ack failed")
    }
    if d=r.diagnostics(start.Add(330*time.Millisecond));d.DeliveredFrames!=2{
        t.Fatalf("empty poll counted as delivered DATA: %+v",d)
    }
}

func TestReverseBBRJitterWindowIsBoundedAndRequiresRealData(t *testing.T) {
    start:=time.Unix(1850000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{33},32),start)
    // An authenticated but idle session does not warrant permanent 500pps.
    if got:=r.pollPeriod(start.Add(time.Minute),1,true);got!=25*time.Millisecond {
        t.Fatalf("open but inactive UDP session should stay at 25ms: %s",got)
    }
    r.noteOutboundFrame(start)
    if got:=r.pollPeriod(start.Add(100*time.Millisecond),1,true);got!=12*time.Millisecond {
        t.Fatalf("one outbound frame must not enable maximum 2ms polling: %s",got)
    }
    if got:=r.pollPeriod(start.Add(9*time.Second),1,true);got!=25*time.Millisecond {
        t.Fatalf("one stale outbound frame permanently raised ICMP poll rate: %s",got)
    }
    // A real sustained outbound video burst holds fast polls through a
    // 3-second BBR ACK/congestion-recovery silence, then returns to idle.
    for i:=0;i<5;i++{r.noteOutboundFrame(start.Add(time.Duration(i*30)*time.Millisecond))}
    if got:=r.pollPeriod(start.Add(3*time.Second),1,true);got!=4*time.Millisecond {
        t.Fatalf("BBR jitter guard should stay at 4ms: %s",got)
    }
    if got:=r.pollPeriod(start.Add(6*time.Second),1,true);got!=12*time.Millisecond {
        t.Fatalf("BBR jitter guard must back off: %s",got)
    }
    if got:=r.pollPeriod(start.Add(9*time.Second),0,true);got!=250*time.Millisecond {
        t.Fatalf("idle tunnel must return to 250ms: %s",got)
    }
    if got:=r.pollPeriod(start.Add(9*time.Second),0,false);got!=200*time.Millisecond {
        t.Fatalf("handshake must retain bounded 200ms probes: %s",got)
    }
}

func TestReverseQueueLatencyRollingP95SeparatesTransientStalls(t *testing.T) {
    now:=time.Unix(1850000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{34},32),now)
    initial:=r.diagnostics(now)
    if initial.MeanQueueDelayMs!=0 || initial.P95QueueDelayMs!=0 ||
        initial.DeliveryDelaySampleCount!=0 {
        t.Fatalf("empty queue history must be empty: %+v",initial)
    }
    // Simulate 120 fast successful Echo writes and eight transient
    // one-second delays. Nearest-rank P95 must report the tail.
    for i:=0;i<128;i++{
        delay:=10*time.Millisecond
        if i>=120 {delay=time.Second}
        r.noteDeliveredFrame(now.Add(-delay),now)
    }
    d:=r.diagnostics(now)
    if d.DeliveryDelaySampleCount!=128 || d.DeliveredFrames!=128 ||
        d.MeanQueueDelayMs!=71 || d.P95QueueDelayMs!=1000 ||
        d.VeryDelayedFrames!=8 || d.DelayedFrames!=8 {
        t.Fatalf("rolling queue latency failed to reveal 1s spikes: %+v",d)
    }
    // After 128 new healthy frames, the rolling window must recover,
    // despite the lifetime very-slow count remaining visible.
    for i:=0;i<128;i++{
        r.noteDeliveredFrame(now.Add(-20*time.Millisecond),now)
    }
    d=r.diagnostics(now)
    if d.DeliveryDelaySampleCount!=128 || d.MeanQueueDelayMs!=20 ||
        d.P95QueueDelayMs!=20 || d.DeliveredFrames!=256 ||
        d.VeryDelayedFrames!=8 {
        t.Fatalf("rolling P95 retained obsolete stall or lost lifetime stats: %+v",d)
    }
}
