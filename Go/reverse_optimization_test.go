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
    if got:=r.pollPeriod(now.Add(50*time.Millisecond),1,true);got!=24*time.Millisecond{
        t.Fatalf("isolated data caused too many polls: %s",got)
    }
    r.noteUsefulFrame(now.Add(100*time.Millisecond))
    if got:=r.pollPeriod(now.Add(150*time.Millisecond),1,true);got!=12*time.Millisecond{
        t.Fatalf("warm reverse interval %s",got)
    }
    r.noteUsefulFrame(now.Add(160*time.Millisecond))
    r.noteUsefulFrame(now.Add(200*time.Millisecond))
    if got:=r.pollPeriod(now.Add(250*time.Millisecond),1,true);got!=2*time.Millisecond{
        t.Fatalf("sustained reverse throughput capped at %s",got)
    }
    if got:=r.pollPeriod(now.Add(2*time.Second),1,true);got!=24*time.Millisecond{
        t.Fatalf("stale reverse traffic should cool: %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),1,true);got!=24*time.Millisecond{
        t.Fatalf("quiet but connected reverse interval %s",got)
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

func TestReversePollPredictsQUICAcknowledgementsFromDownstream(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{27},32),now)
    // No connections/no traffic still sends low-rate polls.
    if got:=r.pollPeriod(now,0,true);got!=250*time.Millisecond{
        t.Fatalf("unexpected idle traffic overhead: %s",got)
    }
    // A foreign-origin UDP DATA packet predicts a near-future upstream ACK.
    r.noteDownstreamFrame(now)
    if got:=r.pollPeriod(now.Add(10*time.Millisecond),0,true);got!=16*time.Millisecond{
        t.Fatalf("downstream packet did not trigger ACK-poll anticipation: %s",got)
    }
    for _,offset:=range []time.Duration{50,100,150} {
        r.noteDownstreamFrame(now.Add(offset*time.Millisecond))
    }
    if got:=r.pollPeriod(now.Add(175*time.Millisecond),0,true);got!=8*time.Millisecond{
        t.Fatalf("sustained video traffic did not accelerate polls: %s",got)
    }
    if got:=r.pollPeriod(now.Add(2*time.Second),0,true);got!=250*time.Millisecond{
        t.Fatalf("stale video traffic left excessive poll rate: %s",got)
    }
    // Direct-mode negotiation must not be made more aggressive.
    if got:=r.pollPeriod(now,1,false);got!=200*time.Millisecond{
        t.Fatalf("handshake pacing unexpectedly changed: %s",got)
    }
    d:=r.diagnostics(now.Add(2*time.Second))
    if d.DownstreamFrames!=4 || d.PollIntervalMillis!=200 {
        t.Fatalf("inaccurate foreign-outbound diagnostics: %+v",d)
    }
}

func TestReverseQueueWaitLatencyMeasuredOnlyAfterSuccessfulSend(t *testing.T) {
    now:=time.Unix(1810000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{28},32),now)
    if !r.enqueue([]byte("ack"),now){t.Fatal("enqueue")}
    if got:=r.diagnostics(now.Add(220*time.Millisecond)).QueueOldestAgeMs;got!=220{
        t.Fatalf("missing queue age, got %d",got)
    }
    // A failed socket write restores original enqueue timestamp; the next
    // successful attempt, not the failed attempt, counts as delivered.
    if sendQueuedReverse(r,now.Add(100*time.Millisecond),func([]byte)bool{return false}) {
        t.Fatal("failed send unexpectedly succeeded")
    }
    if d:=r.diagnostics(now.Add(300*time.Millisecond));d.QueueWaitSamples!=0||d.QueueOldestAgeMs!=300{
        t.Fatalf("failed attempt altered the queue age or stats: %+v",d)
    }
    if !sendQueuedReverse(r,now.Add(350*time.Millisecond),func(body []byte)bool{return string(body)=="ack"}) {
        t.Fatal("encrypted reply was not sent")
    }
    d:=r.diagnostics(now.Add(time.Second))
    if d.QueueWaitSamples!=1 || d.QueueWaitMaxMs!=350 || d.QueueWaitEWMAms!=350 ||
       d.QueueOldestAgeMs!=0 || d.Pending!=0 {
        t.Fatalf("invalid measured queue latency: %+v",d)
    }
    // Next sample: EWMA is responsive and bounded, max retains worst sample.
    if !r.enqueue([]byte("ack2"),now.Add(time.Second)){t.Fatal("enqueue 2")}
    if !sendQueuedReverse(r,now.Add(1100*time.Millisecond),func([]byte)bool{return true}) {
        t.Fatal("second delivery failed")
    }
    d=r.diagnostics(now.Add(2*time.Second))
    if d.QueueWaitSamples!=2 || d.QueueWaitMaxMs!=350 ||
       d.QueueWaitEWMAms<330 || d.QueueWaitEWMAms>345 {
        t.Fatalf("queue EWMA failed: %+v",d)
    }
}
