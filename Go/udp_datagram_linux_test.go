package pingtunnel

import (
    "bytes"
    "net"
    "testing"
    "time"
)

func TestReadUDPDatagramKeepsLargePacketIntact(t *testing.T) {
    listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }
    defer listener.Close()
    sender, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
    if err != nil { t.Fatal(err) }
    defer sender.Close()
    payload := bytes.Repeat([]byte("QUIC-datagram-"), 2500) // > 2 KiB and 10 KiB
    if _, err := sender.Write(payload); err != nil { t.Fatal(err) }
    if err := listener.SetReadDeadline(time.Now().Add(3*time.Second)); err != nil { t.Fatal(err) }
    buffer := make([]byte, udpMaxDatagramBytes)
    n, from, truncated, err := readUDPDatagram(listener, buffer)
    if err != nil { t.Fatal(err) }
    if truncated || from == nil || n != len(payload) || !bytes.Equal(buffer[:n], payload) {
        t.Fatalf("large UDP datagram corrupted: n=%d expected=%d truncated=%t addr=%v",n,len(payload),truncated,from)
    }
}

func TestReadUDPDatagramDetectsTruncation(t *testing.T) {
    listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }
    defer listener.Close()
    sender, err := net.DialUDP("udp4",nil,listener.LocalAddr().(*net.UDPAddr))
    if err != nil { t.Fatal(err) }
    defer sender.Close()
    payload := bytes.Repeat([]byte("UDP"), 2000)
    if _, err := sender.Write(payload); err != nil { t.Fatal(err) }
    if err := listener.SetReadDeadline(time.Now().Add(3*time.Second)); err != nil { t.Fatal(err) }
    before := udpTruncatedDatagrams.Load()
    n,_,truncated,err := readUDPDatagram(listener,make([]byte,512))
    if err != nil { t.Fatal(err) }
    if !truncated || n != 512 || udpTruncatedDatagrams.Load() != before+1 {
        t.Fatalf("truncation was not detected: n=%d truncated=%t",n,truncated)
    }
}
