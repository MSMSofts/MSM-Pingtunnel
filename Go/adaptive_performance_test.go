package pingtunnel

import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "time"
)

func sampleAdaptive(a *AdaptivePerformance,at time.Time,rtt time.Duration) {
 a.OnPing(at)
 a.OnPong(at,at.Add(rtt))
}

func TestAdaptiveLearnsFromExistingPingsWithoutRestart(t *testing.T) {
 a:=NewAdaptivePerformance()
 defaults:=a.Parameters(1048576,20000,400)
 if defaults.Window!=20000 || defaults.ResendMs!=400 {
  t.Fatalf("initial settings changed: %+v",defaults)
 }
 now:=time.Now()
 for i:=0;i<10;i++ {sampleAdaptive(a,now.Add(time.Duration(i)*time.Second),80*time.Millisecond)}
 out:=a.Parameters(1048576,20000,400)
 if out.ResendMs<300 || out.ResendMs>500 || out.Window!=20000 {
  t.Fatalf("unexpected learned settings: %+v",out)
 }
}

func TestAdaptiveMissedProbeIsNotIdleTime(t *testing.T) {
 a:=NewAdaptivePerformance()
 now:=time.Now()
 sampleAdaptive(a,now,60*time.Millisecond)
 a.OnTick(now.Add(3*time.Hour))
 st:=a.Status(1048576,20000,400)
 if st.Profile!="stable" || st.LossEstimate!=0 {
  t.Fatalf("idle misclassified as loss: %+v",st)
 }
}

func TestAdaptiveDegradesAndRecoversWithHysteresis(t *testing.T) {
 a:=NewAdaptivePerformance()
 now:=time.Now()
 for i:=0;i<6;i++ {sampleAdaptive(a,now.Add(time.Duration(i)*time.Second),90*time.Millisecond)}
 for i:=0;i<3;i++ {
  at:=now.Add(time.Duration(100+i*10)*time.Second)
  a.OnPing(at)
  a.OnTick(at.Add(6*time.Second))
 }
 unhealthy:=a.Parameters(1048576,20000,400)
 if unhealthy.Window>=20000 || unhealthy.ResendMs<400 {
  t.Fatalf("expected conservative settings after loss: %+v",unhealthy)
 }
 for i:=0;i<40;i++ {
  at:=now.Add(time.Duration(1000+i)*time.Second)
  sampleAdaptive(a,at,90*time.Millisecond)
 }
 recovered:=a.Parameters(1048576,20000,400)
 if recovered.Window!=20000 {
  t.Fatalf("controller failed to recover from transient loss: %+v",recovered)
 }
}

func TestAdaptiveIgnoresOldPongs(t *testing.T) {
 a:=NewAdaptivePerformance()
 now:=time.Now()
 a.OnPing(now)
 next:=now.Add(time.Second)
 a.OnPing(next)
 // Out-of-order responses are valid while the old probe is outstanding.
 a.OnPong(now,now.Add(40*time.Millisecond))
 if a.Status(1048576,20000,400).Samples!=1 {t.Fatal("did not accept outstanding earlier probe")}
 a.OnPong(next,next.Add(50*time.Millisecond))
 if a.Status(1048576,20000,400).Samples!=2 {t.Fatal("did not accept current probe response")}
 a.OnPong(now,now.Add(80*time.Millisecond))
 if a.Status(1048576,20000,400).Samples!=2 {t.Fatal("accepted duplicate response")}
}

func TestAdaptiveStatusIsSecretFreeAndPrivate(t *testing.T) {
 a:=NewAdaptivePerformance()
 now:=time.Now()
 sampleAdaptive(a,now,100*time.Millisecond)
 path:=filepath.Join(t.TempDir(),"performance.json")
 a.WriteStatus(path,1048576,20000,400)
 info,err:=os.Stat(path)
 if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600 {t.Fatalf("status permission: %o",info.Mode().Perm())}
 raw,err:=os.ReadFile(path)
 if err!=nil{t.Fatal(err)}
 var value map[string]interface{}
 if err=json.Unmarshal(raw,&value);err!=nil{t.Fatal(err)}
 if value["rtt_samples"]!=float64(1) || value["profile"]!="stable" {t.Fatalf("unexpected status: %s",raw)}
}

func TestContinuousPingsWithoutPongsRegistersLoss(t *testing.T){
 a:=NewAdaptivePerformance()
 base:=time.Now()
 for i:=0;i<20;i++ {
  at:=base.Add(time.Duration(i)*time.Second)
  a.OnPing(at)
  a.OnTick(at)
 }
 st:=a.Status(1<<20,20000,400)
 if st.Profile!="degraded" || st.LossEstimate<=0 {
  t.Fatalf("continuous unanswered probes were incorrectly healthy: %+v",st)
 }
 if len(a.outstanding)>16{t.Fatalf("old probes still retained: %d",len(a.outstanding))}
}

func TestReorderedPongsForSeparateOutstandingPings(t *testing.T){
 a:=NewAdaptivePerformance()
 base:=time.Now()
 a.OnPing(base)
 a.OnPing(base.Add(time.Second))
 a.OnPong(base,base.Add(120*time.Millisecond))
 a.OnPong(base.Add(time.Second),base.Add(time.Second+80*time.Millisecond))
 st:=a.Status(1<<20,20000,400)
 if st.Samples!=2||st.LossEstimate!=0{t.Fatalf("valid reordered pong ignored: %+v",st)}
}
