package pingtunnel

import (
    "sync"
    "sync/atomic"
    "time"

    "github.com/esrrhs/gohome/network"
)

// The upstream esrrhs/pingtunnel solution to shared-ICMP socket
// starvation sends a bounded quantum from each TCP FrameMgr before
// yielding to the next waiting flow. Large TCP windows must not dump
// megabytes into the kernel in a single uncapped burst.
//
// Keep UDP and authenticated control outside this TCP fairness gate:
// a large TCP transfer must not delay latency-sensitive UDP traffic.
const icmpTCPShareQuantum = 8 * 1024

// The TCP fairness gate is per VPS core instance, not per service/port.
// It covers connection-open, active stream, AND close/drain loops.
type icmpTCPFairShare struct {
    mu sync.Mutex
    waiters []chan struct{}
    held bool

    contended atomic.Uint64
    maxWaitMs atomic.Uint64
    turns atomic.Uint64
}

func (s *icmpTCPFairShare) lock() {
    start:=time.Now()
    s.mu.Lock()
    if !s.held {
        s.held=true
        s.mu.Unlock()
        return
    }
    waiter:=make(chan struct{})
    s.waiters=append(s.waiters,waiter)
    s.contended.Add(1)
    s.mu.Unlock()
    <-waiter
    waited:=uint64(time.Since(start)/time.Millisecond)
    for old:=s.maxWaitMs.Load();waited>old;old=s.maxWaitMs.Load() {
        if s.maxWaitMs.CompareAndSwap(old,waited) {break}
    }
}

func (s *icmpTCPFairShare) unlock() {
    s.mu.Lock()
    if len(s.waiters)==0 {
        s.held=false
        s.mu.Unlock()
        return
    }
    waiter:=s.waiters[0]
    s.waiters[0]=nil // do not retain channels in an idle backing array
    s.waiters=s.waiters[1:]
    if len(s.waiters)==0 {s.waiters=nil}
    s.mu.Unlock()
    // Fair handoff: s.held stays true, preventing a noisy flow from
    // stealing the turn from a waiter before it has resumed.
    close(waiter)
}

func (s *icmpTCPFairShare) emitFrames(frames []*network.Frame, send func(*network.Frame) int) {
    if len(frames)==0 || send==nil {return}
    if s==nil {
        for _,f:=range frames {send(f)}
        return
    }
    for i:=0;i<len(frames); {
        s.lock()
        budget:=icmpTCPShareQuantum
        func() {
            defer s.unlock()
            for i<len(frames) && budget>0 {
                written:=send(frames[i])
                // Invalid/zero-size control frames must still count
                // against the quantum, avoiding an unbounded burst.
                if written<1 {written=1}
                budget-=written
                i++
            }
            s.turns.Add(1)
        }()
    }
}

// Collect the already-admitted FrameMgr frames without changing their order,
// congestion window, or retransmission decisions. No FrameMgr lock is held
// while a flow waits for its turn.
func collectFairFrames(n int, next func(func(*network.Frame))) []*network.Frame {
    if n<=0{return nil}
    result:=make([]*network.Frame,0,n)
    next(func(f *network.Frame) {result=append(result,f)})
    return result
}
