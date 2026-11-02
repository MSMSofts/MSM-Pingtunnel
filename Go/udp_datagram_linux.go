package pingtunnel

import (
    "net"
    "syscall"
    "sync/atomic"
)

// Match the largest UDP datagram that can be carried by a UDP socket.
// A shorter buffer silently truncates datagrams and can corrupt QUIC frames.
const udpMaxDatagramBytes = 65535

var udpTruncatedDatagrams atomic.Uint64

// readUDPDatagram reports kernel truncation as an explicit drop rather than
// forwarding only the prefix of an application datagram. This is Linux-only
// because the tunnel's production systemd service targets Linux.
func readUDPDatagram(conn *net.UDPConn, dst []byte) (int, *net.UDPAddr, bool, error) {
    n, _, flags, from, err := conn.ReadMsgUDP(dst, nil)
    if err != nil { return n, from, false, err }
    truncated := flags&syscall.MSG_TRUNC != 0
    if truncated { udpTruncatedDatagrams.Add(1) }
    return n, from, truncated, nil
}
