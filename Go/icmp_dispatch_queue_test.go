package pingtunnel

import (
    "testing"
    "time"
)

func TestUDPDispatchSaturationDoesNotBlockICMPReceiver(t *testing.T) {
    if packetQueueCapacity(true) != 256 ||
        packetQueueCapacity(false) != 10000 {
        t.Fatal("unexpected UDP/TCP queue capacities")
    }
    queue := make(chan *Packet, 1)
    queue <- &Packet{my: &MyMsg{Type: int32(MyMsg_DATA)}}
    before := udpIngressOverflowDrops.Load()
    start := time.Now()
    if !enqueueICMPPacket(queue, &Packet{my: &MyMsg{Type: int32(MyMsg_DATA)}}, true) {
        t.Fatal("UDP overload should not kill the ICMP reader")
    }
    if time.Since(start) >= 100*time.Millisecond {
        t.Fatal("UDP queue overload blocked the sole ICMP receiver")
    }
    if got := udpIngressOverflowDrops.Load(); got != before+1 {
        t.Fatalf("expected one explicit drop, got %d", got-before)
    }
    if len(queue) != 1 {
        t.Fatal("UDP overflow must not grow the pending queue")
    }
}

func TestUDPControlPacketsAreNotSilentlyDropped(t *testing.T) {
    queue := make(chan *Packet, 1)
    queue <- &Packet{my: &MyMsg{Type: int32(MyMsg_DATA)}}
    before := udpIngressOverflowDrops.Load()
    go func() {
        time.Sleep(10*time.Millisecond)
        <-queue
    }()
    control := &Packet{my: &MyMsg{Type: int32(MyMsg_KICK)}}
    if !enqueueICMPPacket(queue, control, true) {
        t.Fatal("UDP control was not delivered")
    }
    if got := <-queue; got != control {
        t.Fatal("wrong control message delivered")
    }
    if udpIngressOverflowDrops.Load() != before {
        t.Fatal("UDP control message counted as a dropped datagram")
    }
}

func TestTCPDispatcherKeepsLosslessBackpressure(t *testing.T) {
    queue := make(chan *Packet, 1)
    queue <- &Packet{my: &MyMsg{Type: int32(MyMsg_DATA)}}
    before := udpIngressOverflowDrops.Load()
    go func() {
        time.Sleep(10*time.Millisecond)
        <-queue
    }()
    p := &Packet{my: &MyMsg{Type: int32(MyMsg_DATA)}}
    if !enqueueICMPPacket(queue, p, false) || <-queue != p {
        t.Fatal("TCP packet silently dropped under temporary queue pressure")
    }
    if udpIngressOverflowDrops.Load() != before {
        t.Fatal("TCP saturation counted as UDP packet loss")
    }
}
