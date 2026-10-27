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
    if got:=r.pollPeriod(now.Add(50*time.Millisecond),1,true);got!=30*time.Millisecond{
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
    if got:=r.pollPeriod(now.Add(2*time.Second),1,true);got!=30*time.Millisecond{
        t.Fatalf("stale reverse traffic should cool: %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),1,true);got!=60*time.Millisecond{
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

func TestDuplexReversePollPacingFollowsDownlinkWithoutACKs(t *testing.T) {
    now:=time.Unix(1830000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0xa7},32),now)
    if p:=r.pollPeriod(now,1,true);p!=60*time.Millisecond {
        t.Fatalf("quiet open UDP flow too slow: %s",p)
    }
    // Foreign may continuously transmit the video stream while QUIC ACKs
    // are missing from the reverse path. Pacing must NOT depend only on
    // receiving Iran-side frames.
    r.noteDownstreamFrame(now)
    if p:=r.pollPeriod(now.Add(50*time.Millisecond),1,true);p!=12*time.Millisecond {
        t.Fatalf("first downstream DATA did not warm reverse polls: %s",p)
    }
    for i:=1;i<=5;i++ {
        r.noteDownstreamFrame(now.Add(time.Duration(i)*70*time.Millisecond))
    }
    if p:=r.pollPeriod(now.Add(400*time.Millisecond),1,true);p!=4*time.Millisecond {
        t.Fatalf("sustained video downlink did not accelerate ACK opportunities: %s",p)
    }
    // Natural gaps should not immediately collapse polling to 60-250 ms.
    if p:=r.pollPeriod(now.Add(3*time.Second),1,true);p!=24*time.Millisecond {
        t.Fatalf("downlink cool-down skipped warm stage: %s",p)
    }
    if p:=r.pollPeriod(now.Add(6*time.Second),1,true);p!=45*time.Millisecond {
        t.Fatalf("downlink cool-down skipped medium stage: %s",p)
    }
    if p:=r.pollPeriod(now.Add(9*time.Second),1,true);p!=60*time.Millisecond {
        t.Fatalf("stale activity should return to open-connection interval: %s",p)
    }
    if p:=r.pollPeriod(now.Add(9*time.Second),0,true);p!=250*time.Millisecond {
        t.Fatalf("completely idle tunnel should not flood polls: %s",p)
    }
    d:=r.diagnostics(now.Add(9*time.Second))
    if d.LastDownstreamAgeSeconds!=8 {t.Fatalf("unexpected downstream age: %+v",d)}
}

func TestReverseQueueWaitTelemetry(t *testing.T) {
    now:=time.Unix(1830000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{12},32),now)
    r.enqueue([]byte("a"),now)
    r.enqueue([]byte("b"),now)
    if got:=r.take(now.Add(100*time.Millisecond));string(got)!="a"{t.Fatalf("FIFO: %q",got)}
    if got:=r.take(now.Add(900*time.Millisecond));string(got)!="b"{t.Fatalf("FIFO: %q",got)}
    d:=r.diagnostics(now.Add(time.Second))
    if d.DequeueSamples!=2 || d.DequeueMaxWaitMs!=900 ||
       d.DequeueWaitEWMAMs<100 || d.DequeueWaitEWMAMs>900 {
        t.Fatalf("invalid bounded queue-wait telemetry: %+v",d)
    }
    // Neither stale frames nor idle polls should count as successful dequeues.
    r.enqueue([]byte("stale"),now)
    _=r.take(now.Add(13*time.Second))
    e:=r.diagnostics(now.Add(13*time.Second))
    if e.DequeueSamples!=2 || e.QueueDrops!=1 {
        t.Fatalf("expired frame inflated queue-wait samples: %+v",e)
    }
}
