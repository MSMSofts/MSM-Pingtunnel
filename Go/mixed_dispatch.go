package pingtunnel

import (
    "sync/atomic"
    "time"
)

// In mixed Multi-Port the ICMP reader is shared by TCP and UDP. A full
// 10,000-entry TCP queue must never block the reader for the old 3-second
// reliable-queue timeout: doing so also stalls unrelated UDP/game traffic.
// This bounded overload policy applies ONLY to mixed TCP DATA. FrameMgr's
// reliable TCP framing retransmits lost DATA; control messages are not dropped.
// A short grace absorbs momentary full-queue scheduling races.
const mixedTCPAdmissionGrace = 2 * time.Millisecond

var tcpIngressOverflowDrops atomic.Uint64

func enqueueMixedTCPData(queue chan<- *Packet, packet *Packet) bool {
    select {
    case queue <- packet:
        return true
    default:
    }
    timer := time.NewTimer(mixedTCPAdmissionGrace)
    defer timer.Stop()
    select {
    case queue <- packet:
        return true
    case <-timer.C:
        tcpIngressOverflowDrops.Add(1)
        return true
    }
}

// Preserve the legacy single-port behavior. In mixed mode separate TCP and
// UDP queues, and let control traffic bypass a full TCP queue via the short
// UDP queue (which never silently drops authenticated control packets).
func enqueueAuthenticatedPacketByTransport(
    reliable chan<- *Packet,
    udpRecv chan<- *Packet,
    packet *Packet,
    legacyUDP bool,
) bool {
    if udpRecv != nil {
        if packet != nil && packet.my != nil {
            if packet.my.Type == int32(MyMsg_DATA) {
                if packet.my.Tcpmode == 0 {
                    return enqueueICMPPacket(udpRecv,packet,true)
                }
                return enqueueMixedTCPData(reliable,packet)
            }
            // A full TCP DATA queue cannot hold back authenticated
            // control traffic needed for session and flow recovery.
            select {
            case reliable <- packet:
                return true
            default:
                return enqueueICMPPacket(udpRecv,packet,false)
            }
        }
        return enqueueICMPPacket(reliable,packet,false)
    }
    return enqueueICMPPacket(reliable,packet,legacyUDP)
}
