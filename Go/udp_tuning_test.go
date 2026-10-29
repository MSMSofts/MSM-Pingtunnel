package pingtunnel

import "testing"

func TestUDPBufferSizeBoundsAndTransportIsolation(t *testing.T) {
    udp := &Client{tcpmode: 0}
    for _, size := range []int{0, 64 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 2 * 1024 * 1024} {
        if err := udp.SetUDPBufferSize(size); err != nil {
            t.Fatalf("unexpected UDP buffer rejection for %d: %v", size, err)
        }
        if udp.udpSocketBuffer != size {
            t.Fatalf("UDP buffer size not retained: got %d, want %d", udp.udpSocketBuffer, size)
        }
    }
    for _, invalid := range []int{-1, 1, 64*1024 - 1, 2*1024*1024 + 1} {
        if err := udp.SetUDPBufferSize(invalid); err == nil {
            t.Errorf("invalid UDP socket buffer %d was accepted", invalid)
        }
    }
    tcp := &Client{tcpmode: 1}
    if err := tcp.SetUDPBufferSize(512 * 1024); err == nil {
        t.Error("TCP mode unexpectedly accepted UDP buffer override")
    }
    if tcp.udpSocketBuffer != 0 {
        t.Error("failed override modified TCP-mode UDP setting")
    }
}
