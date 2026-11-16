package pingtunnel

import (
    "bytes"
    "fmt"
    "testing"
    "time"
)

func newReversePriorityFixture(t *testing.T) (*reverseTransport,time.Time) {
    t.Helper()
    now:=time.Unix(1900000000,0)
    r,err:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x42},32),now)
    if err!=nil {t.Fatal(err)}
    return r,now
}
func TestReversePriorityUDPCannotBeDisplacedByTCP(t *testing.T) {
    r,now:=newReversePriorityFixture(t)
    for i:=0;i<reverseQueueMaxFrames;i++ {
        if !r.enqueue([]byte(fmt.Sprintf("tcp-%03d",i)),now,
            reverseFrameMeta{class:reverseTrafficTCP,service:"S01"}) {t.Fatal("TCP seed failed")}
    }
    if !r.enqueue([]byte("game-udp"),now,reverseFrameMeta{class:reverseTrafficUDP,service:"S02"}) {
        t.Fatal("UDP must evict old TCP, not be dropped")
    }
    first,ok:=r.takeFrame(now)
    if !ok||string(first.data)!="game-udp" {t.Fatalf("interactive UDP not first: %q",first.data)}
    if r.priorityTCPDrops!=1 || r.priorityUDPDrops!=0 {t.Fatalf("wrong drop classes TCP=%d UDP=%d",r.priorityTCPDrops,r.priorityUDPDrops)}
    // Once UDP/control have filled the FIFO, incoming bulk TCP is shed.
    r2,at:=newReversePriorityFixture(t)
    for i:=0;i<reverseQueueMaxFrames;i++ {
        if !r2.enqueue([]byte{byte(i)},at,reverseFrameMeta{class:reverseTrafficUDP}) {t.Fatal("UDP seed failed")}
    }
    if r2.enqueue([]byte("bulk"),at,reverseFrameMeta{class:reverseTrafficTCP}) {t.Fatal("TCP must not evict UDP")}
    if r2.priorityTCPDrops!=1 || r2.priorityUDPDrops!=0 {t.Fatal("drop accounting")}
}
func TestReversePriorityWeightedFairnessAndPerServiceOrder(t *testing.T) {
    r,now:=newReversePriorityFixture(t)
    for i:=0;i<12;i++ {
        r.enqueue([]byte(fmt.Sprintf("udp-%02d",i)),now,reverseFrameMeta{class:reverseTrafficUDP,service:"S02"})
    }
    for i:=0;i<4;i++ {
        r.enqueue([]byte(fmt.Sprintf("tcp-%02d",i)),now,reverseFrameMeta{class:reverseTrafficTCP,service:"S01"})
    }
    expected:=[]string{"udp-00","udp-01","udp-02","udp-03","tcp-00","udp-04","udp-05","udp-06","udp-07","tcp-01"}
    for i,want:=range expected {
        frame,ok:=r.takeFrame(now)
        if !ok||string(frame.data)!=want {t.Fatalf("schedule[%d]: %q != %q",i,frame.data,want)}
    }
    if r.priorityTCPDequeues!=2 || r.priorityUDPDequeues!=8 {t.Fatal("wrong share")}
    service,at:=newReversePriorityFixture(t)
    for _,f:=range []struct{s,v string}{{"S02","a1"},{"S02","a2"},{"S04","b1"},{"S04","b2"}} {
        service.enqueue([]byte(f.v),at,reverseFrameMeta{class:reverseTrafficUDP,service:f.s})
    }
    for i,want:=range []string{"a1","b1","a2","b2"} {
        frame,ok:=service.takeFrame(at)
        if !ok||string(frame.data)!=want {t.Fatalf("service fairness[%d]=%q want %s",i,frame.data,want)}
    }
}
func TestReversePriorityControlAndFailedWritePreserveFrame(t *testing.T) {
    r,now:=newReversePriorityFixture(t)
    for i:=0;i<reverseQueueMaxFrames;i++ {
        r.enqueue([]byte{byte(i)},now,reverseFrameMeta{class:reverseTrafficUDP,service:"S02"})
    }
    if !r.enqueue([]byte("X25519-control"),now,reverseFrameMeta{class:reverseTrafficControl}) {
        t.Fatal("control must be admitted under data congestion")
    }
    control,ok:=r.takeFrame(now)
    if !ok || string(control.data)!="X25519-control" {t.Fatal("control was starved")}
    r.restoreFront(control,now.Add(time.Millisecond))
    restored,ok:=r.takeFrame(now.Add(2*time.Millisecond))
    if !ok||!bytes.Equal(restored.data,control.data) {t.Fatal("failed control write was not restored")}
    if r.failedReplies!=1 || r.priorityControlDrops!=0 {t.Fatal("control restore accounting")}
}
func TestReversePriorityBoundedMemoryAndTTL(t *testing.T) {
    r,now:=newReversePriorityFixture(t)
    for i:=0;i<5000;i++ {
        meta:=reverseFrameMeta{class:reverseTrafficTCP,service:"S01"}
        if i%3==0 {meta=reverseFrameMeta{class:reverseTrafficUDP,service:"S02"}}
        r.enqueue(bytes.Repeat([]byte{byte(i)},4096),now,meta)
        if len(r.pending)>reverseQueueMaxFrames || r.pendingBytes>reverseQueueMaxBytes {
            t.Fatalf("unbounded reverse queue: frames=%d bytes=%d",len(r.pending),r.pendingBytes)
        }
    }
    for {
        _,ok:=r.takeFrame(now.Add(reverseFrameTTL+time.Millisecond))
        if !ok {break}
        t.Fatal("expired frame was delivered")
    }
    if len(r.pending)!=0 || r.pendingBytes!=0 {t.Fatal("expired frames still held")}
}
