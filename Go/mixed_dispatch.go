package pingtunnel

import (
    "sync/atomic"
    "time"
)

// v3.3.24 ran one application protocol per process. Mixed Multi-Port must
// isolate TCP, UDP, and control through the *complete* receive/dispatch path:
// separate channels alone do not help when one slow TCP handler is shared.
const mixedControlQueueCapacity = 128

var tcpIngressOverflowDrops atomic.Uint64
var mixedUDPQueueMaxDelayMs atomic.Uint64
var mixedTCPQueueMaxDelayMs atomic.Uint64
var mixedUDPQueueOver250ms atomic.Uint64
var mixedTCPQueueOver250ms atomic.Uint64

// Under sustained saturation, waiting even 2ms on each TCP frame can build
// a multi-second ICMP read stall. The TCP FrameMgr already handles loss and
// retransmission, so shed an overflowing mixed TCP DATA frame immediately.
// The legacy single-port reliable queue keeps its unchanged behavior.
func enqueueMixedTCPData(queue chan<- *Packet, packet *Packet) bool {
    select {
    case queue <- packet:
    default:
        tcpIngressOverflowDrops.Add(1)
    }
    return true
}

// v3.3.24 UDP admission is strict FIFO with drop-INCOMING-DATA when full.
 // The receiver does not evict an earlier accepted datagram to make room for
 // a newer one; that speculative policy was introduced only after Multi-Port.
 // The legacy helper is shared by single-port and mixed-port UDP lanes.
 // Control messages continue on the independent reliable lane.
// The mixed control lane and its goroutine never carry UDP data, avoiding
// accidental eviction of a PING/KICK frame during a UDP overload. Control
// remains reliable, with the established 3s fatal backpressure behavior
// reserved for exceptional, fully saturated control traffic.
func enqueueAuthenticatedPacketByTransport(
    reliable chan<- *Packet,
    udpRecv chan *Packet,
    packet *Packet,
    legacyUDP bool,
    control ...chan<- *Packet,
) bool {
    if udpRecv == nil {
        return enqueueICMPPacket(reliable, packet, legacyUDP)
    }
    if packet == nil || packet.my == nil {
        return enqueueICMPPacket(reliable, packet, false)
    }
    if packet.my.Type == int32(MyMsg_DATA) {
        if packet.my.Tcpmode == 0 {
            // Exact v3.3.24 UDP DATA FIFO admission: never evict a queued
            // packet; an overflowing incoming datagram is counted and dropped.
            // Keeping the independent UDP dispatch lane prevents unrelated
            // TCP connect/FrameMgr work from blocking this legacy path.
            return enqueueICMPPacket(udpRecv, packet, true)
        }
        return enqueueMixedTCPData(reliable, packet)
    }
    if len(control) > 0 && control[0] != nil {
        return enqueueICMPPacket(control[0], packet, false)
    }
    // Legacy helper compatibility: control may share the non-TCP channel,
    // and must never be discarded during congestion.
    select {
    case reliable <- packet:
        return true
    default:
        return enqueueICMPPacket(udpRecv, packet, false)
    }
}

// Dedicated workers for all three packet classes prevent a 1s destination
// connect, a slow TCP FrameMgr, or a congested thread-pool submission from
// delaying UDP delivery. A closed stop channel broadcasts to every worker.
func runMixedDispatchLane(stop <-chan int, packets <-chan *Packet, handler func(*Packet)) {
    for {
        select {
        case <-stop:
            return
        case packet, ok := <-packets:
            if !ok {
                return
            }
            if packet != nil {
                observeMixedDispatchDelay(packet)
                handler(packet)
            }
        }
    }
}

func observeMixedDispatchDelay(packet *Packet) {
    if packet == nil || packet.my == nil || packet.receivedAt.IsZero() {
        return
    }
    age:=time.Since(packet.receivedAt)
    if age<0 {return}
    ms:=uint64(age/time.Millisecond)
    if packet.my.Type!=int32(MyMsg_DATA) {return}
    maxValue:=&mixedTCPQueueMaxDelayMs
    slowValue:=&mixedTCPQueueOver250ms
    if packet.my.Tcpmode==0 {
        maxValue=&mixedUDPQueueMaxDelayMs
        slowValue=&mixedUDPQueueOver250ms
    }
    for old:=maxValue.Load();ms>old;old=maxValue.Load() {
        if maxValue.CompareAndSwap(old,ms) {break}
    }
    if age>250*time.Millisecond {slowValue.Add(1)}
}
