package pingtunnel

import (
    "sync"
    "sync/atomic"
)

// registerLiveWorker serializes dynamic WaitGroup.Add operations with the
// transition to shutdown. Once shutdown begins, no later Add is possible.
// This closes the positive-Add vs Wait race for accepted TCP/SOCKS/UDP flows.
func registerLiveWorker(exiting *atomic.Bool, gate *sync.Mutex, wg *sync.WaitGroup) bool {
    gate.Lock()
    defer gate.Unlock()
    if exiting.Load() {return false}
    wg.Add(1)
    return true
}
func beginCoreShutdown(exiting *atomic.Bool, gate *sync.Mutex) bool {
    gate.Lock()
    defer gate.Unlock()
    return exiting.CompareAndSwap(false,true)
}
func (p *Client) beginWorker() bool {
    return registerLiveWorker(&p.exit,&p.workerRegistrationMu,&p.workResultLock)
}
func (p *Server) beginWorker() bool {
    return registerLiveWorker(&p.exit,&p.workerRegistrationMu,&p.workResultLock)
}
