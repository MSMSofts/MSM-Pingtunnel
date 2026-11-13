package pingtunnel

import "time"

// Adapted from the current upstream esrrhs/pingtunnel idle-loop scheduler.
// Preserve the same minimum/maximum waits; unlike time.After on every
// iteration, arm() reuses one timer. Allocate lazily so TCP sessions that
// never need an idle wait do not allocate a timer at all.
type adaptiveLoopWait struct {
    min time.Duration
    max time.Duration
    cur time.Duration
    t *time.Timer
}

func newAdaptiveLoopWait(min,max time.Duration) adaptiveLoopWait {
    if min<=0 {min=time.Millisecond}
    if max<min {max=min}
    return adaptiveLoopWait{min:min,max:max,cur:min}
}

func (a *adaptiveLoopWait) arm(d time.Duration) <-chan time.Time {
    if d<time.Millisecond {d=time.Millisecond}
    if a.t==nil {
        a.t=time.NewTimer(d)
        return a.t.C
    }
    if !a.t.Stop() {
        select{case <-a.t.C:default:}
    }
    a.t.Reset(d)
    return a.t.C
}

func (a *adaptiveLoopWait) stop() {
    if a.t!=nil {
        a.t.Stop()
        a.t=nil
    }
}

func (a *adaptiveLoopWait) hit() {a.cur=a.min}

func (a *adaptiveLoopWait) miss() time.Duration {
    current:=a.cur
    next:=a.cur*2
    if next>a.max {next=a.max}
    a.cur=next
    return current
}
