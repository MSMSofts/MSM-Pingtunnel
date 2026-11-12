package pingtunnel

// enqueueAuthenticatedPacketByTransport applies the existing per-protocol
// queue policies without reconfiguring their capacities, drop rules or TCP
// backpressure. In legacy single-port mode udpRecv=nil and all original
// behavior is preserved. In mixed Multi-Port mode only UDP application DATA
// uses the existing bounded, latency-sensitive UDP queue.
func enqueueAuthenticatedPacketByTransport(
    reliable chan<- *Packet,
    udpRecv chan<- *Packet,
    packet *Packet,
    legacyUDP bool,
) bool {
    if udpRecv != nil {
        if packet != nil && packet.my != nil &&
            packet.my.Type == int32(MyMsg_DATA) && packet.my.Tcpmode == 0 {
            return enqueueICMPPacket(udpRecv,packet,true)
        }
        return enqueueICMPPacket(reliable,packet,false)
    }
    return enqueueICMPPacket(reliable,packet,legacyUDP)
}
