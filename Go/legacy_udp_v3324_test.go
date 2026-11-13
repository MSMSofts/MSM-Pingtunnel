package pingtunnel

import (
 "fmt"
 "testing"
 "time"
)

// Baseline: v3.3.24 enqueued authenticated UDP DATA FIFO in a 256-slot
// bounded channel; a full queue drops the *new* datagram without removing
// an already accepted packet. Multi-Port must reproduce exactly the same
// admission sequence even when an independent control lane is supplied.
func TestMultiUDPAdmissionMatchesV3324ForAllQueueStates(t *testing.T) {
 for _,capUDP:=range []int{1,3,16,256} {
  t.Run(fmt.Sprintf("capacity_%d",capUDP),func(t *testing.T) {
   baseline:=make(chan *Packet,capUDP)
   multi:=make(chan *Packet,capUDP)
   tcp:=make(chan *Packet,2)
   ctrl:=make(chan *Packet,2)
   baselineDropped:=udpIngressOverflowDrops.Load()
   for i:=0;i<capUDP+50;i++{
    msg:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0,
      Id:fmt.Sprintf("S02-flow-%04d",i)}}
    if !enqueueICMPPacket(baseline,msg,true) {
     t.Fatal("legacy UDP enqueue unexpectedly blocked")
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,multi,msg,false,ctrl) {
     t.Fatal("mixed compatibility UDP admission unexpectedly blocked")
    }
   }
   if len(baseline)!=capUDP || len(multi)!=capUDP {
    t.Fatalf("wrong FIFO queue occupancy: baseline %d mixed %d",len(baseline),len(multi))
   }
   for i:=0;i<capUDP;i++ {
    a,b:=(<-baseline).my.Id,(<-multi).my.Id
    want:=fmt.Sprintf("S02-flow-%04d",i)
    if a!=want||b!=want {
     t.Fatalf("legacy FIFO order changed at %d: original=%s mixed=%s want=%s",i,a,b,want)
    }
   }
   if got:=udpIngressOverflowDrops.Load()-baselineDropped;got!=100{
    t.Fatalf("each of the two identical FIFO dispatchers must record 50 overflow drops: %d",got)
   }
   if len(tcp)!=0||len(ctrl)!=0{
    t.Fatal("UDP DATA leaked into TCP or control dispatcher")
   }
  })
 }
}

func TestLegacyUDPOverflowDoesNotEvictControlOrDelayReader(t *testing.T){
 udp:=make(chan *Packet,1)
 tcp:=make(chan *Packet,1)
 ctrl:=make(chan *Packet,1)
 first:=&Packet{my:&MyMsg{Id:"first",Type:int32(MyMsg_DATA),Tcpmode:0}}
 if !enqueueAuthenticatedPacketByTransport(tcp,udp,first,false,ctrl) {
  t.Fatal("first UDP data rejected")
 }
 start:=time.Now()
 for i:=0;i<10000;i++{
  m:=&Packet{my:&MyMsg{Id:"new",Type:int32(MyMsg_DATA),Tcpmode:0}}
  if !enqueueAuthenticatedPacketByTransport(tcp,udp,m,false,ctrl) {
   t.Fatal("full UDP FIFO blocked receiver")
  }
 }
 if time.Since(start)>time.Second {
  t.Fatal("legacy UDP overflow blocked ICMP receiver")
 }
 if got:=<-udp;got!=first {
  t.Fatal("overload evicted an already-admitted UDP datagram")
 }
 ping:=&Packet{my:&MyMsg{Type:int32(MyMsg_PING)}}
 if !enqueueAuthenticatedPacketByTransport(tcp,udp,ping,false,ctrl) {
  t.Fatal("control PING rejected")
 }
 if got:=<-ctrl;got!=ping {
  t.Fatal("control frame lost under legacy UDP saturation")
 }
 if len(tcp)!=0||len(udp)!=0 {t.Fatal("cross-lane contamination")}
}

func TestV3324UDPQueueCapacityRemains256(t *testing.T) {
 if packetQueueCapacity(true)!=256 || packetQueueCapacity(false)!=10000 {
  t.Fatal("legacy v3.3.24 dispatcher capacities were modified")
 }
}
