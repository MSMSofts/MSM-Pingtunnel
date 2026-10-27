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
    if got:=r.pollPeriod(now.Add(50*time.Millisecond),1,true);got!=2*time.Millisecond{
        t.Fatalf("active reverse throughput capped at %s",got)
    }
    if got:=r.pollPeriod(now.Add(2*time.Second),1,true);got!=12*time.Millisecond{
        t.Fatalf("warm reverse interval %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),1,true);got!=80*time.Millisecond{
        t.Fatalf("quiet but connected reverse interval %s",got)
    }
    if got:=r.pollPeriod(now.Add(10*time.Second),0,true);got!=250*time.Millisecond{
        t.Fatalf("idle reverse interval %s",got)
    }
    d:=r.diagnostics(now.Add(10*time.Second))
    if d.PollIntervalMillis!=250 || d.LastUsefulFrameAgeSeconds!=10{
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
        if len(body)!=0{t.Fatal("expired frame was emitted")}
        return true
    }){t.Fatal("empty poll acknowledgement failed")}
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
