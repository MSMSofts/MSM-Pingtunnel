package pingtunnel

import "testing"

// Verify the ICMP receive side can accept every single-packet IPv4 message
// representable by the Linux raw socket, including larger UDP payloads.
func TestICMPReceiveBufferCoversMaximumIPv4Datagram(t *testing.T) {
    if icmpReadBufferBytes < udpMaxDatagramBytes {
        t.Fatalf("ICMP receive buffer %d is smaller than UDP max %d",
            icmpReadBufferBytes,udpMaxDatagramBytes)
    }
}
