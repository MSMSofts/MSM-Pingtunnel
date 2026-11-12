package pingtunnel

import (
    "testing"
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
