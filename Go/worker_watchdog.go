package pingtunnel

import (
 "fmt"
 "os"
 "sync/atomic"
 "github.com/esrrhs/gohome/loggo"
)

// A dead ICMP receiver/dispatcher with a still-live idle main goroutine is
// unhealthy. Make systemd Restart=on-failure effective. No network silence
// or filtering automatically kills an otherwise healthy Go worker.
func workerStoppedUnexpectedly(shuttingDown *atomic.Bool) bool {
 return !shuttingDown.Load()
}
func failOnUnexpectedWorkerExit(name string,shuttingDown *atomic.Bool){
 if workerStoppedUnexpectedly(shuttingDown) {
  loggo.Error("critical Pingtunnel worker %s exited unexpectedly; restarting Go core via systemd",name)
  fmt.Fprintf(os.Stderr, "pingtunnel: critical worker %s stopped; systemd restart requested\n", name)
  os.Exit(1)
 }
}
