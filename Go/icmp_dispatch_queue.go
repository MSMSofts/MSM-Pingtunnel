package pingtunnel

import (
    "sync/atomic"
    "time"
)

// TCP flows retain the existing generous lossless dispatcher. UDP/QUIC
// prioritizes a short pending queue over accumulating seconds-old game packets.
// This is only the authenticated application dispatch queue, not the socket
// receive buffer or the Wire v4 encrypted replay window.
const udpDispatchQueueCapacity = 256
const tcpDispatchQueueCapacity = 10000

var udpIngressOverflowDrops atomic.Uint64

func packetQueueCapacity(udpMode bool) int {
    if udpMode {
        return udpDispatchQueueCapacity
    }
    return tcpDispatchQueueCapacity
}

// Return false only if the receiver is fatally blocked. An authenticated UDP
// DATA packet may be deliberately discarded when its queue is saturated;
// waiting 3 seconds would freeze the only ICMP reader and amplify lag. Never
// discard control packets or change TCP's existing backpressure semantics.
func enqueueICMPPacket(queue chan<- *Packet, packet *Packet, udpMode bool) bool {
    select {
    case queue <- packet:
        return true
    default:
        if udpMode && packet != nil && packet.my != nil &&
            packet.my.Type == int32(MyMsg_DATA) {
            udpIngressOverflowDrops.Add(1)
            return true
        }
    }

    stalled := time.NewTimer(3 * time.Second)
    defer stalled.Stop()
    select {
    case queue <- packet:
        return true
    case <-stalled.C:
        return false
    }
}
