package pingtunnel

import (
    "sync"
    "sync/atomic"
    "testing"
)

func TestWorkerRegistrationRejectsPostShutdownAdd(t *testing.T) {
    var exit atomic.Bool
    var gate sync.Mutex
    var wg sync.WaitGroup
    if !registerLiveWorker(&exit,&gate,&wg) {t.Fatal("first worker rejected")}
    wg.Done()
    if !beginCoreShutdown(&exit,&gate) {t.Fatal("shutdown refused")}
    if registerLiveWorker(&exit,&gate,&wg) {t.Fatal("accepted worker after shutdown")}
    wg.Wait()
}
func TestWorkerRegistrationConcurrentStopAndWait(t *testing.T) {
    for round:=0;round<20;round++ {
        var exit atomic.Bool
        var gate sync.Mutex
        var workers sync.WaitGroup
        var starters sync.WaitGroup
        const n=64
        starters.Add(n)
        for i:=0;i<n;i++ {
            go func() {
                defer starters.Done()
                if registerLiveWorker(&exit,&gate,&workers) {
                    defer workers.Done()
                }
            }()
        }
        // The gate ensures Wait observes every worker that was registered
        // before shutdown, and later starters are refused.
        if !beginCoreShutdown(&exit,&gate) {t.Fatal("unexpected already stopped")}
        workers.Wait()
        starters.Wait()
        if registerLiveWorker(&exit,&gate,&workers) {t.Fatal("late Add after Wait")}
        workers.Wait()
    }
}
