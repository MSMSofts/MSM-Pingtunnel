package pingtunnel

// Conservative adaptive initial TCP settings based on existing ICMP ping RTTs.
// The upstream BB congestion controller remains active for established flows.
// Never restart the tunnel or mutate in-flight FrameMgr windows.
import (
 "encoding/json"
 "math"
 "os"
 "sync"
 "time"
)
type AdaptiveFrameSettings struct {
 BufferBytes int
 Window int
 ResendMs int
}
type AdaptivePerformance struct {
 mu sync.Mutex
 outstanding []time.Time
 samples uint64
 srttMs, jitterMs, baseMs float64
 lossScore float64
 misses, recovery int
 degraded bool
 lastPongAt time.Time
}
func NewAdaptivePerformance() *AdaptivePerformance { return &AdaptivePerformance{} }
func (a *AdaptivePerformance) OnPing(sent time.Time) {
 a.mu.Lock()
 defer a.mu.Unlock()
 a.expireProbesLocked(sent)
 // Each probe is tracked independently: a one-second cadence must not
 // erase older unanswered probes before their 5-15 second deadline.
 a.outstanding=append(a.outstanding,sent)
 if len(a.outstanding)>64 {
  a.noteLossLocked()
  a.outstanding=a.outstanding[1:]
 }
}
func (a *AdaptivePerformance) OnPong(sent, received time.Time) {
 a.mu.Lock()
 defer a.mu.Unlock()
 index:=-1
 for i,probe:=range a.outstanding {
  if probe.Equal(sent){index=i;break}
 }
 if index<0{return}
 a.outstanding=append(a.outstanding[:index],a.outstanding[index+1:]...)
 rtt:=float64(received.Sub(sent))/float64(time.Millisecond)
 if rtt<=0 || rtt>60000{return}
 if a.samples==0 {
  a.srttMs=rtt; a.jitterMs=rtt/2; a.baseMs=rtt
 } else {
  a.jitterMs=0.75*a.jitterMs+0.25*math.Abs(a.srttMs-rtt)
  a.srttMs=0.875*a.srttMs+0.125*rtt
  if rtt<a.baseMs {a.baseMs=0.80*a.baseMs+0.20*rtt
  }else{a.baseMs=0.995*a.baseMs+0.005*rtt}
 }
 a.samples++
 a.lastPongAt=received
 a.lossScore*=0.82
 a.misses=0
 spike:=a.samples>=4 && rtt>math.Max(250,a.baseMs*2.5)
 if a.lossScore>=0.16||spike {
  a.degraded=true; a.recovery=0
 }else if a.degraded{
  a.recovery++
  if a.recovery>=5 && a.lossScore<0.08 {a.degraded=false}
 }
}
// Idle periods with no outstanding ping never count as loss.
func (a *AdaptivePerformance) OnTick(now time.Time) {
 a.mu.Lock()
 defer a.mu.Unlock()
 a.expireProbesLocked(now)
}
func (a *AdaptivePerformance) expireProbesLocked(now time.Time) {
 if len(a.outstanding)==0{return}
 cutoff:=a.timeoutLocked()
 survivors:=a.outstanding[:0]
 for _,sent:=range a.outstanding{
  if !now.Before(sent) && now.Sub(sent)>=cutoff {
   a.noteLossLocked()
  }else{
   survivors=append(survivors,sent)
  }
 }
 a.outstanding=survivors
}
func (a *AdaptivePerformance) timeoutLocked() time.Duration {
 ms:=5000.0
 if a.samples>0 && a.srttMs*4+a.jitterMs*4>ms {ms=a.srttMs*4+a.jitterMs*4}
 if ms>15000 {ms=15000}
 return time.Duration(ms*float64(time.Millisecond))
}
func (a *AdaptivePerformance) noteLossLocked() {
 a.lossScore=math.Min(1,a.lossScore*0.80+0.25)
 a.misses++; a.recovery=0
 if a.misses>=2||a.lossScore>=0.30 {a.degraded=true}
}
func clampAdaptive(v,lo,hi int) int {
 if v<lo{return lo};if v>hi{return hi};return v
}
func (a *AdaptivePerformance) parametersLocked(bufferBytes,maxWindow,rto int) AdaptiveFrameSettings {
 p:=AdaptiveFrameSettings{BufferBytes:bufferBytes,Window:maxWindow,ResendMs:rto}
 if a.samples==0 {
  // A completely silent ICMP path provides no RTT sample, but repeated
  // timed-out probes still mean we must slow new TCP handshakes.
  if a.degraded {
   p.Window=clampAdaptive(maxWindow/2,256,10000)
   p.ResendMs=clampAdaptive(rto*2,800,2400)
  }
  return p
 }
 p.ResendMs=clampAdaptive(int(math.Round(a.srttMs+4*a.jitterMs+80)),300,2000)
 if a.degraded {
  p.Window=clampAdaptive(maxWindow/2,256,10000)
  p.ResendMs=clampAdaptive(p.ResendMs*3/2,400,2400)
 }
 return p
}
func (a *AdaptivePerformance) Parameters(bufferBytes,maxWindow,rto int) AdaptiveFrameSettings {
 a.mu.Lock();defer a.mu.Unlock()
 return a.parametersLocked(bufferBytes,maxWindow,rto)
}
type adaptiveStatus struct {
 Profile string `json:"profile"`
 Samples uint64 `json:"rtt_samples"`
 LastSampleAgeSeconds int64 `json:"last_rtt_sample_age_seconds"`
 RTTMs float64 `json:"rtt_ms"`
 JitterMs float64 `json:"jitter_ms"`
 LossEstimate float64 `json:"probe_loss_estimate"`
 ResendMs int `json:"next_tcp_resend_ms"`
 Window int `json:"next_tcp_window"`
 ExistingSessions string `json:"existing_sessions"`
}
func (a *AdaptivePerformance) Status(bufferBytes,maxWindow,rto int) adaptiveStatus {
 a.mu.Lock();defer a.mu.Unlock()
 p:=a.parametersLocked(bufferBytes,maxWindow,rto)
 profile:="learning"
 age:=int64(-1)
 if !a.lastPongAt.IsZero() {
  since:=time.Since(a.lastPongAt)
  if since<0 {since=0}
  age=int64(since/time.Second)
 }
 if a.degraded {profile="degraded"} else if a.samples>0 {profile="stable"}
 return adaptiveStatus{
  Profile:profile, Samples:a.samples, LastSampleAgeSeconds:age,
  RTTMs:math.Round(a.srttMs*10)/10,
  JitterMs:math.Round(a.jitterMs*10)/10,
  LossEstimate:math.Round(a.lossScore*1000)/1000,
  ResendMs:p.ResendMs,Window:p.Window,
  ExistingSessions:"BB congestion stays active; adaptive initial settings affect only new TCP sessions",
 }
}
func (a *AdaptivePerformance) WriteStatus(path string,bufferBytes,maxWindow,rto int) {
 data,err:=json.Marshal(a.Status(bufferBytes,maxWindow,rto))
 if err!=nil{return}
 tmp:=path+".pending"
 if err=os.WriteFile(tmp,data,0600);err!=nil{return}
 if err=os.Rename(tmp,path);err!=nil{_ = os.Remove(tmp)}
}
