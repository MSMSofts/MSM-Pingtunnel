package pingtunnel

import (
    "sync"
    "testing"
    "time"
)

func TestMultiPortDispatchIsolatesUDPCongestionFromTCP(t *testing.T) {
    tcp := make(chan *Packet, packetQueueCapacity(false))
    udp := make(chan *Packet, packetQueueCapacity(true))
    if cap(tcp)!=tcpDispatchQueueCapacity || cap(udp)!=udpDispatchQueueCapacity {
        t.Fatal("Multi-Port changed the legacy protocol queue capacities")
    }
    udpData:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0}}
    tcpData:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}}
    control:=&Packet{my:&MyMsg{Type:int32(MyMsg_PING),Tcpmode:0}}
    before:=udpIngressOverflowDrops.Load()
    for i:=0;i<udpDispatchQueueCapacity+100;i++ {
        if !enqueueAuthenticatedPacketByTransport(tcp,udp,udpData,false) {
            t.Fatal("UDP congestion must use the previous nonblocking drop policy")
        }
    }
    if got:=udpIngressOverflowDrops.Load()-before;got!=100 {
        t.Fatalf("expected 100 UDP overflow drops, got %d",got)
    }
    if len(udp)!=udpDispatchQueueCapacity || len(tcp)!=0 {
        t.Fatalf("unexpected mixed queue lengths: tcp=%d udp=%d",len(tcp),len(udp))
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,tcpData,false) {
        t.Fatal("TCP DATA must remain lossless and independent of congested UDP")
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,control,false) {
        t.Fatal("control traffic must never be dropped because of congested UDP")
    }
    if len(tcp)!=2 || len(udp)!=udpDispatchQueueCapacity {
        t.Fatalf("TCP/control isolated enqueue failed: tcp=%d udp=%d",len(tcp),len(udp))
    }
}

func TestLegacySinglePortQueueSemanticsUnchanged(t *testing.T) {
    for _, legacyUDP := range []bool{false,true} {
        q:=make(chan *Packet,packetQueueCapacity(legacyUDP))
        packet:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0}}
        if !enqueueAuthenticatedPacketByTransport(q,nil,packet,legacyUDP) || len(q)!=1 {
            t.Fatalf("legacy UDP=%v queue behavior changed",legacyUDP)
        }
    }
}


func TestMixedTCPQueueSaturationDoesNotBlockUDP(t *testing.T) {
    tcp := make(chan *Packet, 1)
    udp := make(chan *Packet, 1)
    tcp <- &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}}
    before := tcpIngressOverflowDrops.Load()
    started := time.Now()
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,
        &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}},false) {
        t.Fatal("bounded TCP overload must preserve ICMP reader")
    }
    if time.Since(started)>100*time.Millisecond {
        t.Fatal("TCP saturation stalled the shared ICMP reader")
    }
    if tcpIngressOverflowDrops.Load()!=before+1 {
        t.Fatal("TCP overload counter was not updated")
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,
        &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0}},false) {
        t.Fatal("UDP should enqueue while TCP is saturated")
    }
    if len(udp)!=1 || len(tcp)!=1 {
        t.Fatal("TCP saturation affected UDP admission or TCP queue length")
    }
}

func TestMixedControlBypassesSaturatedTCPDataQueue(t *testing.T) {
    tcp:=make(chan *Packet,1)
    udp:=make(chan *Packet,1)
    tcp <- &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}}
    control:=&Packet{my:&MyMsg{Type:int32(MyMsg_KICK)}}
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,control,false) {
        t.Fatal("control traffic must not be discarded")
    }
    if got:=<-udp;got!=control {
        t.Fatal("authenticated control did not bypass congested TCP")
    }
}

func TestMixedTCPBurstBelowCapacityIsLossless(t *testing.T) {
    tcp:=make(chan *Packet,256)
    udp:=make(chan *Packet,256)
    before:=tcpIngressOverflowDrops.Load()
    for i:=0;i<256;i++ {
        if !enqueueAuthenticatedPacketByTransport(tcp,udp,
            &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}},false) {
            t.Fatal("normal TCP burst rejected")
        }
    }
    if len(tcp)!=256 || tcpIngressOverflowDrops.Load()!=before {
        t.Fatal("normal TCP burst must not drop")
    }
}

func TestMixedDropsOldUDPNotNewestWhenControlLaneIsolated(t *testing.T) {
    reliable:=make(chan *Packet,1)
    udp:=make(chan *Packet,3)
    control:=make(chan *Packet,1)
    for _,id:=range []string{"old-A","old-B","old-C","fresh-D"} {
        packet:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0,Id:id}}
        if !enqueueAuthenticatedPacketByTransport(reliable,udp,packet,false,control) {
            t.Fatal("UDP overflow must not stall the ICMP receiver")
        }
    }
    got:=[]string{(<-udp).my.Id,(<-udp).my.Id,(<-udp).my.Id}
    for i,id:=range []string{"old-B","old-C","fresh-D"} {
        if got[i]!=id {t.Fatalf("expected fresh-only bounded queue, got %v",got)}
    }
    // Control is never enqueued in the evicting UDP lane.
    ping:=&Packet{my:&MyMsg{Type:int32(MyMsg_PING)}}
    if !enqueueAuthenticatedPacketByTransport(reliable,udp,ping,false,control) {
        t.Fatal("authenticated control must not drop")
    }
    if got:=<-control;got!=ping {t.Fatal("control did not use dedicated lane")}
    if len(reliable)!=0 {t.Fatal("control unexpectedly occupied the TCP lane")}
}

func TestMixedTCPSaturationNeverSpendsTwoMillisecondsPerPacket(t *testing.T) {
    tcp:=make(chan *Packet,1)
    udp:=make(chan *Packet,1)
    control:=make(chan *Packet,1)
    tcp<-&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}}
    packet:=&Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}}
    start:=time.Now()
    for i:=0;i<1000;i++{
        if !enqueueAuthenticatedPacketByTransport(tcp,udp,packet,false,control) {
            t.Fatal("mixed TCP overflow must be bounded and counted")
        }
    }
    if time.Since(start)>400*time.Millisecond {
        t.Fatal("1000 saturated TCP frames stalled the raw ICMP reader")
    }
    if len(udp)!=0 || len(control)!=0 {
        t.Fatal("TCP overload contaminated UDP/control")
    }
}

func TestMixedProtocolHandlersAreIndependent(t *testing.T) {
    tcp:=make(chan *Packet,1)
    udp:=make(chan *Packet,1)
    control:=make(chan *Packet,1)
    done:=make(chan int)
    tcpEntered:=make(chan struct{})
    releaseTCP:=make(chan struct{})
    udpDelivered:=make(chan struct{})
    controlDelivered:=make(chan struct{})
    var wg sync.WaitGroup
    wg.Add(3)
    go func() {defer wg.Done();runMixedDispatchLane(done,tcp,func(*Packet) {
        close(tcpEntered)
        <-releaseTCP // simulate a 1s foreign TCP connect delay
    })}()
    go func() {defer wg.Done();runMixedDispatchLane(done,udp,func(*Packet) {
        close(udpDelivered)
    })}()
    go func() {defer wg.Done();runMixedDispatchLane(done,control,func(*Packet) {
        close(controlDelivered)
    })}()
    defer func(){close(releaseTCP);close(done);wg.Wait()}()
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,
        &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:1}},false,control) {
        t.Fatal("TCP enqueue")
    }
    select {
    case <-tcpEntered:
    case <-time.After(time.Second):t.Fatal("TCP worker not scheduled")
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,
        &Packet{my:&MyMsg{Type:int32(MyMsg_DATA),Tcpmode:0}},false,control) {
        t.Fatal("UDP enqueue")
    }
    if !enqueueAuthenticatedPacketByTransport(tcp,udp,
        &Packet{my:&MyMsg{Type:int32(MyMsg_PING)}},false,control) {
        t.Fatal("control enqueue")
    }
    timeout:=time.NewTimer(400*time.Millisecond)
    defer timeout.Stop()
    for udpDelivered!=nil || controlDelivered!=nil {
        select {
        case <-udpDelivered:udpDelivered=nil
        case <-controlDelivered:controlDelivered=nil
        case <-timeout.C:t.Fatal("blocked TCP prevented UDP or control delivery")
        }
    }
}
