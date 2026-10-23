package pingtunnel

import(
 "encoding/binary"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

// Exercise the real Client's shared ICMP sequence counter under parallel
// TCP / UDP / heartbeat-like senders, not just source-level inspection.
func TestParallelICMPSequenceUniqueness(t *testing.T){
 c:=&Client{}
 const workers=12
 const perWorker=500
 results:=make(chan int,workers*perWorker)
 var wg sync.WaitGroup
 for w:=0;w<workers;w++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   for j:=0;j<perWorker;j++{results<-c.nextSequence()}
  }()
 }
 wg.Wait()
 close(results)
 seen:=make(map[int]bool)
 for seq:=range results {
  if seq<=0 || seq>65535 || seen[seq] {
   t.Fatalf("ICMP sequence duplicated/out of range under concurrent sends: %d",seq)
  }
  seen[seq]=true
 }
 if len(seen)!=workers*perWorker{t.Fatalf("incomplete sequences %d",len(seen))}
}

func TestWorkerSupervisionHonorsGracefulShutdown(t *testing.T){
 var stopping atomic.Bool
 if !workerStoppedUnexpectedly(&stopping){t.Fatal("unexpected worker shutdown not identified")}
 stopping.Store(true)
 if workerStoppedUnexpectedly(&stopping){t.Fatal("normal service shutdown classified as failure")}
}

func TestParallelSessionAEADAndStatus(t *testing.T){
 iran,foreign:=newSecurePair(t)
 const workers=10
 const perWorker=80
 frames:=make(chan []byte,workers*perWorker)
 var wg sync.WaitGroup
 for worker:=0;worker<workers;worker++{
  wg.Add(1)
  go func(w int){
   defer wg.Done()
   for j:=0;j<perWorker;j++{
    raw:=make([]byte,8)
    binary.BigEndian.PutUint32(raw[:4],uint32(w))
    binary.BigEndian.PutUint32(raw[4:],uint32(j))
    sealed,err:=iran.Encrypt(raw)
    if err!=nil{t.Errorf("session encrypt: %v",err);return}
    frames<-sealed
    _=iran.SecureStats()
    _=foreign.SecureStats()
   }
  }(worker)
 }
 wg.Wait()
 close(frames)
 // Read after sorting by authenticated seq: traffic over ICMP may be
 // reordered, but anything >1024 packets behind the newest is invalid.
 var all [][]byte
 for frame:=range frames{all=append(all,frame)}
 for i:=1;i<len(all);i++{
  current:=all[i]
  idx:=i
  for idx>0 && binary.BigEndian.Uint64(all[idx-1][21:29])>binary.BigEndian.Uint64(current[21:29]){
    all[idx]=all[idx-1]
    idx--
  }
  all[idx]=current
 }
 for _,frame:=range all{
  plain,err:=foreign.Decrypt(frame)
  if err!=nil||len(plain)!=8{t.Fatalf("concurrently sealed frame failed: %v",err)}
 }
 if foreign.SecureStats().ReplayDrops!=0{t.Fatal("legitimate frames unexpectedly replayed")}
}

func TestHandshakeRetransmissionAfterDroppedReply(t *testing.T){
 key:=pairedTestKey(t)
 iran,err:=NewCryptoConfig(AUTO,key);if err!=nil{t.Fatal(err)}
 foreign,err:=NewCryptoConfig(AUTO,key);if err!=nil{t.Fatal(err)}
 if err=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
 if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
 if err=iran.BindSecurePeer("203.0.113.5");err!=nil{t.Fatal(err)}
 if err=foreign.BindSecurePeer("203.0.113.4");err!=nil{t.Fatal(err)}
 now:=time.Now()
 first,err:=iran.SecureControl(now)
 if err!=nil{t.Fatal(err)}
 lostServerReply,err:=foreign.ReceiveSecureControl(first,now)
 if err!=nil||len(lostServerReply)==0{t.Fatalf("hello reply: %v",err)}
 // Drop the first HelloReply; client retransmits the original signed hello.
 retry,err:=iran.SecureControl(now.Add(2*time.Second))
 if err!=nil||len(retry)==0{t.Fatalf("client did not retry: %v",err)}
 again,err:=foreign.ReceiveSecureControl(retry,now.Add(2*time.Second))
 if err!=nil || string(again)!=string(lostServerReply){t.Fatal("server regenerated ephemeral key for retransmitted Hello")}
 finish,err:=iran.ReceiveSecureControl(again,now.Add(2*time.Second))
 if err!=nil{t.Fatal(err)}
 ack,err:=foreign.ReceiveSecureControl(finish,now.Add(2*time.Second))
 if err!=nil{t.Fatal(err)}
 // ACK was lost. Send Finish again using the time-bounded retransmitter.
 finishedRetry,err:=iran.SecureControl(now.Add(5*time.Second))
 if err!=nil||len(finishedRetry)==0{t.Fatal("client did not retransmit Finish")}
 ack2,err:=foreign.ReceiveSecureControl(finishedRetry,now.Add(5*time.Second))
 if err!=nil || string(ack2)!=string(ack){t.Fatal("final confirmation retransmit not idempotent")}
 if _,err=iran.ReceiveSecureControl(ack2,now.Add(5*time.Second));err!=nil{t.Fatal(err)}
 if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("did not recover when HelloReply/Ack were lost")}
}
