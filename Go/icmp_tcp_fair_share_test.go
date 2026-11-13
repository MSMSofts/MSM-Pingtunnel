package pingtunnel

import (
    "sync"
    "testing"
    "time"

    "github.com/esrrhs/gohome/network"
)

// The critical regression: a stream with a large congestion window may not
// fill the entire shared ICMP socket before another waiting TCP stream can
// send one frame. Only one frame may overrun the byte quantum.
func TestTCPFairShareYieldsToWaitingFlowByEightKiB(t *testing.T) {
    share:=&icmpTCPFairShare{}
    entered:=make(chan struct{})
    release:=make(chan struct{})
    firstDone:=make(chan struct{})
    secondDone:=make(chan struct{})
    var mu sync.Mutex
    order:=make([]byte,0,40)
    appendEvent:=func(b byte) {
        mu.Lock()
        order=append(order,b)
        mu.Unlock()
    }
    frames:=func(n int) []*network.Frame {
        out:=make([]*network.Frame,n)
        for i:=range out {out[i]=&network.Frame{}}
        return out
    }
    go func() {
        defer close(firstDone)
        calls:=0
        share.emitFrames(frames(24),func(*network.Frame) int {
            appendEvent('A')
            calls++
            if calls==1 {close(entered);<-release}
            return 1024
        })
    }()
    select {
    case <-entered:
    case <-time.After(time.Second):t.Fatal("first worker not running")
    }
    go func() {
        defer close(secondDone)
        share.emitFrames(frames(3),func(*network.Frame) int {
            appendEvent('B')
            return 1024
        })
    }()
    deadline:=time.After(time.Second)
waiting:
    for {
        if share.contended.Load()>0 {break waiting}
        select {
        case <-deadline:t.Fatal("second flow failed to queue for fair ICMP")
        case <-time.After(time.Millisecond):
        }
    }
    close(release)
    select {
    case <-firstDone:
    case <-time.After(time.Second):t.Fatal("first flow did not finish")
    }
    select {
    case <-secondDone:
    case <-time.After(time.Second):t.Fatal("second flow was starved")
    }
    mu.Lock()
    defer mu.Unlock()
    if len(order)!=27 {t.Fatalf("lost TCP frames: got %d of 27",len(order))}
    firstB:=-1
    countA,countB:=0,0
    for i,evt:=range order {
        if evt=='A'{countA++} else if evt=='B'{countB++;if firstB<0{firstB=i}}
    }
    if countA!=24||countB!=3 {
        t.Fatalf("per-flow frames changed: A=%d B=%d",countA,countB)
    }
    if firstB!=icmpTCPShareQuantum/1024 {
        t.Fatalf("second TCP flow starved behind large first flow: first B at %d, events %s",
            firstB,string(order))
    }
    if share.turns.Load()<4 || tcpICMPFairContended.Load()==0 {
        t.Fatal("fair-share quantum and contention instrumentation missing")
    }
}

func TestTCPFairSharePreservesFrameSequenceAndLargeFrames(t *testing.T) {
    share:=&icmpTCPFairShare{}
    frames:=make([]*network.Frame,0,21)
    for i:=0;i<21;i++ {frames=append(frames,&network.Frame{})}
    count:=0
    share.emitFrames(frames,func(f *network.Frame) int {
        if f!=frames[count] {t.Fatalf("frame order altered at %d",count)}
        count++
        return 20*1024 // one jumbo frame already consumes an entire turn
    })
    if count!=len(frames)||share.turns.Load()!=uint64(len(frames)) {
        t.Fatalf("expected one fair send turn per oversized frame: %d/%d",count,share.turns.Load())
    }
}

func TestTCPFairShareConcurrentFlowCompleteness(t *testing.T) {
    share:=&icmpTCPFairShare{}
    const flows=12
    const framesPerFlow=100
    var wg sync.WaitGroup
    wg.Add(flows)
    for i:=0;i<flows;i++{
        go func(){
            defer wg.Done()
            frames:=make([]*network.Frame,framesPerFlow)
            for j:=range frames{frames[j]=&network.Frame{}}
            count:=0
            share.emitFrames(frames,func(_ *network.Frame) int {count++;return 888})
            if count!=framesPerFlow {t.Errorf("lost frames during concurrent fair-share: %d",count)}
        }()
    }
    done:=make(chan struct{})
    go func(){wg.Wait();close(done)}()
    select{
    case <-done:
    case <-time.After(3*time.Second):t.Fatal("fair ICMP dispatch deadlocked on 12 concurrent TCP flows")
    }
}

func TestTCPFairShareNilReceiverBackwardCompatibility(t *testing.T){
    var share *icmpTCPFairShare
    sent:=0
    share.emitFrames([]*network.Frame{{}},func(*network.Frame) int{sent++;return 0})
    if sent!=1{t.Fatal("nil fair gate must preserve legacy immediate sending")}
    share.emitFrames(nil,func(*network.Frame) int{t.Fatal("empty sendlist must not invoke callback");return 0})
}
