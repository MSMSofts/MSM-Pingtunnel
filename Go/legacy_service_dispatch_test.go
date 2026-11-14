package pingtunnel

import (
    "fmt"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

func TestV3324PerServiceQueueCapacitiesAndIsolation(t *testing.T) {
    protocols:=make(map[string]int)
    for i:=1;i<=12;i++ {
        mode:=0
        if i%2==1 {mode=1}
        protocols[fmt.Sprintf("S%02d",i)]=mode
    }
    d:=newLegacyServiceDispatch(protocols)
    if len(d.lanes)!=12 {t.Fatal("lost mixed service lanes")}
    for id,mode:=range protocols {
        lane:=d.lane(id,int32(mode))
        if lane==nil {t.Fatalf("missing %s lane",id)}
        want:=udpDispatchQueueCapacity
        if mode==1 {want=tcpDispatchQueueCapacity}
        if cap(lane.queue)!=want {
            t.Fatalf("%s got %d slots; v3.3.24 per-service baseline %d",id,cap(lane.queue),want)
        }
        if d.lane(id,int32(1-mode))!=nil {
            t.Fatalf("%s accepted wrong service protocol",id)
        }
    }
    if d.lane("S13",0)!=nil {t.Fatal("unknown service mapped to a real lane")}

    congested:=d.lane("S02",0)
    for i:=0;i<cap(congested.queue)+17;i++ {
        packet:=&Packet{my:&MyMsg{Id:fmt.Sprint(i),Tcpmode:0,Type:int32(MyMsg_DATA)}}
        if !congested.admit(packet){t.Fatal("nonblocking UDP admission failed")}
    }
    if congested.drops.Load()!=17 {t.Fatal("expected exactly 17 UDP drops")}
    freeUDP:=d.lane("S04",0)
    accepted:=&Packet{my:&MyMsg{Id:"independent",Tcpmode:0,Type:int32(MyMsg_DATA)}}
    freeUDP.admit(accepted)
    if len(freeUDP.queue)!=1 || (<-freeUDP.queue)!=accepted {
        t.Fatal("one UDP service saturated all other UDP ports")
    }
    if got:=(<-congested.queue).my.Id;got!="0" {
        t.Fatalf("legacy FIFO evicted first accepted UDP packet: %s",got)
    }

    busyTCP:=d.lane("S01",1)
    for i:=0;i<cap(busyTCP.queue)+23;i++ {
        busyTCP.admit(&Packet{my:&MyMsg{Id:"tcp"}})
    }
    if busyTCP.drops.Load()!=23 {t.Fatal("TCP admission accounting lost")}
    freeTCP:=d.lane("S03",1)
    freeTCP.admit(&Packet{my:&MyMsg{Id:"different-tcp"}})
    if len(freeTCP.queue)!=1 {t.Fatal("one TCP flow consumed another service's 10k queue")}
    snapshot:=d.snapshot()
    if snapshot["S02"].Drops!=17 || snapshot["S04"].Queued!=0 ||
       snapshot["S01"].Capacity!=10000 || snapshot["S03"].Queued!=1 {
        t.Fatalf("per-service live queue snapshot is misleading: %+v",snapshot)
    }
}

// Key regression: v3.4.3-3.4.6 Foreign echoed TCP DATA with
// MyMsg.Tcpmode=0. The old single-port TCP process ignored that bit,
// but Multi-Port used it to put TCP packets in the UDP queue, causing
// QUIC/game packets to compete with TCP data and be discarded.
func TestClientLegacyTCPReplyFlagZeroNeverEntersUDPQueue(t *testing.T) {
    d:=newLegacyServiceDispatch(map[string]int{"S01":1,"S02":0})
    client:=&Client{serviceIngress:d}
    tcpConn:=&ClientConn{id:"tcp-flow",serviceID:"S01",tcpmode:1}
    udpConn:=&ClientConn{id:"udp-flow",serviceID:"S02",tcpmode:0}
    client.localIdToConnMap.Store(tcpConn.id,tcpConn)
    client.localIdToConnMap.Store(udpConn.id,udpConn)
    tcpReply:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Id:tcpConn.id,Tcpmode:0}}
    lane:=client.routeAuthenticatedServiceReply(tcpReply)
    if lane!=d.lane("S01",1) || lane.udp {
        t.Fatal("legitimate TCP reply with legacy Tcpmode=0 was misclassified as UDP")
    }
    lane.admit(tcpReply)
    if len(d.lane("S01",1).queue)!=1 || len(d.lane("S02",0).queue)!=0 {
        t.Fatal("TCP reply contaminated the UDP receive lane")
    }
    udpReply:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Id:udpConn.id,Tcpmode:0}}
    if got:=client.routeAuthenticatedServiceReply(udpReply);got!=d.lane("S02",0){
        t.Fatal("genuine UDP reply was misrouted")
    }
    if got:=client.routeAuthenticatedServiceReply(&Packet{my:&MyMsg{Id:"unknown",Tcpmode:0}});got!=nil{
        t.Fatal("unknown authenticated reply received access to another service")
    }
}

func TestServerAuthenticatedAliasRoutesOnlyMatchingProtocol(t *testing.T) {
    d:=newLegacyServiceDispatch(map[string]int{"S01":1,"S02":0})
    srv:=&Server{
        serviceIngress:d,
        forwardServices:map[string]multiForwardTarget{
            ServiceTarget("S01"):{id:"S01",tcpMode:1,loopback:"127.0.0.1:12001"},
            ServiceTarget("S02"):{id:"S02",tcpMode:0,loopback:"127.0.0.1:12002"},
        },
    }
    for _,tc:=range []struct{id string;mode int32}{
        {"S01",1},{"S02",0},
    } {
        packet:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Target:ServiceTarget(tc.id),Tcpmode:tc.mode}}
        if got:=srv.routeAuthenticatedServiceRequest(packet);got!=d.lane(tc.id,tc.mode) {
            t.Fatalf("correct service %s did not get its private queue",tc.id)
        }
        packet.my.Tcpmode=1-tc.mode
        if got:=srv.routeAuthenticatedServiceRequest(packet);got!=nil{
            t.Fatalf("mismatched protocol %s was accepted into allowlisted queue",tc.id)
        }
    }
    if srv.routeAuthenticatedServiceRequest(&Packet{my:&MyMsg{Target:"evil"}})!=nil{
        t.Fatal("unlisted service reached another service's handler")
    }
}

func TestPreMultiPortServiceWorkersCannotHeadOfLineBlockEachOther(t *testing.T) {
    d:=newLegacyServiceDispatch(map[string]int{"S01":1,"S02":0,"S03":1})
    stop:=make(chan int)
    var closing atomic.Bool
    var wg sync.WaitGroup
    tcpEntered:=make(chan struct{})
    releaseTCP:=make(chan struct{})
    udpDone:=make(chan struct{})
    nextTCPDone:=make(chan struct{})
    defer func() {
        select {case <-releaseTCP:default:close(releaseTCP)}
        closing.Store(true)
        close(stop)
        wg.Wait()
    }()
    d.start(stop,&wg,func(p *Packet) {
        switch p.my.Id {
        case "blocking-tcp":
            close(tcpEntered)
            <-releaseTCP
        case "udp":close(udpDone)
        case "second-tcp":close(nextTCPDone)
        }
    },&closing)
    d.lane("S01",1).admit(&Packet{my:&MyMsg{Id:"blocking-tcp"}})
    select {
    case <-tcpEntered:
    case <-time.After(time.Second):t.Fatal("TCP blocking flow never entered handler")
    }
    d.lane("S02",0).admit(&Packet{my:&MyMsg{Id:"udp"}})
    d.lane("S03",1).admit(&Packet{my:&MyMsg{Id:"second-tcp"}})
    deadline:=time.NewTimer(400*time.Millisecond)
    defer deadline.Stop()
    for udpDone!=nil || nextTCPDone!=nil {
        select{
        case <-udpDone:udpDone=nil
        case <-nextTCPDone:nextTCPDone=nil
        case <-deadline.C:t.Fatal("one service blocked another service's v3.3.24 FIFO worker")
        }
    }
}
