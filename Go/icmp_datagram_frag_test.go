package pingtunnel

import (
    "bytes"
    "encoding/binary"
    "testing"
    "time"
)

func TestEncryptedICMPFragmentBudgetAndOutOfOrderReassembly(t *testing.T) {
    original := bytes.Repeat([]byte("reels-udp-payload-"), 180)
    parts, err := splitAuthenticatedMessage(original)
    if err != nil { t.Fatal(err) }
    if len(parts) < 3 { t.Fatalf("unexpected segment count: %d", len(parts)) }
    for _, part := range parts {
        maxIPv4Bytes := icmpIPv4HeaderBytes + icmpEchoHeaderBytes +
            secureAEADHeaderBytes + secureAEADTagBytes + len(part)
        if maxIPv4Bytes > icmpIPv4PacketBudget {
            t.Fatalf("segment exceeds packet budget: %d", maxIPv4Bytes)
        }
    }
    var r authenticatedReassembler
    now := time.Now()
    for i := len(parts)-1; i >= 1; i-- {
        if payload, complete := r.accept(parts[i], now); complete || payload != nil {
            t.Fatal("incomplete datagram delivered before all fragments")
        }
    }
    result, ok := r.accept(parts[0], now)
    if !ok || !bytes.Equal(result, original) {
        t.Fatal("out-of-order segment reconstruction corrupts UDP datagram")
    }
    if r.buffered != 0 || len(r.groups) != 0 {
        t.Fatal("completed datagram leaked fragment memory")
    }
}
func TestFragmentLossExpiresAndNeverDeliversPartialUDP(t *testing.T) {
    msg := bytes.Repeat([]byte("large-udp"), 200)
    parts, err := splitAuthenticatedMessage(msg)
    if err != nil { t.Fatal(err) }
    var r authenticatedReassembler
    at := time.Now()
    for _, part := range parts[:len(parts)-1] {
        if _, done := r.accept(part, at); done { t.Fatal("unexpected partial delivery") }
    }
    if _, done := r.accept(parts[len(parts)-1], at.Add(fragmentLifetime+time.Second)); done {
        t.Fatal("expired datagram should never be delivered")
    }
    if r.buffered <= 0 { t.Fatal("new standalone tail should be pending") }
    r.prune(at.Add(2*fragmentLifetime+2*time.Second))
    if r.buffered != 0 || len(r.groups) != 0 { t.Fatal("expiry leaked memory") }
}
func TestFragmentStrictLengthsAndDuplicateProtection(t *testing.T) {
    original := bytes.Repeat([]byte("QUIC"), 700)
    parts, err := splitAuthenticatedMessage(original)
    if err != nil { t.Fatal(err) }
    now := time.Now()
    var r authenticatedReassembler
    if _, complete := r.accept(parts[0], now); complete { t.Fatal("early delivery") }
    if _, complete := r.accept(parts[0], now); complete { t.Fatal("duplicate delivered") }
    bogus := append([]byte(nil), parts[1]...)
    binary.BigEndian.PutUint16(bogus[12:14], uint16(len(parts)))
    if _, complete := r.accept(bogus, now); complete { t.Fatal("invalid index accepted") }
    altered := append([]byte(nil), parts[1]...)
    binary.BigEndian.PutUint32(altered[16:20], 42)
    if _, complete := r.accept(altered, now); complete { t.Fatal("wrong length accepted") }
    for _, part := range parts[1:] {
        result, ok := r.accept(part, now)
        if ok && !bytes.Equal(result, original) { t.Fatal("corrupted message") }
        if ok { return }
    }
    t.Fatal("valid chunks were not reassembled after invalid peers")
}
func TestShortMessageRemainsWireCompatibleAndLargeInputBounded(t *testing.T) {
    short := []byte("unchanged protobuf message")
    parts, err := splitAuthenticatedMessage(short)
    if err != nil || len(parts)!=1 || !bytes.Equal(parts[0],short) {
        t.Fatal("small frames must remain bit-identical")
    }
    big := make([]byte, fragmentMaxOriginalBytes+1)
    if _, err := splitAuthenticatedMessage(big); err == nil {
        t.Fatal("oversized message must be rejected, never IP fragmented")
    }
}
func TestFragmentReassemblyMemoryBoundUnderManyPartialDatagrams(t *testing.T) {
    var r authenticatedReassembler
    now := time.Now()
    for i := 0; i < 90; i++ {
        data := bytes.Repeat([]byte{byte(i)}, fragmentMaxOriginalBytes)
        chunks, err := splitAuthenticatedMessage(data)
        if err != nil { t.Fatal(err) }
        if _, done := r.accept(chunks[0], now); done { t.Fatal("early delivery") }
        if r.buffered > fragmentMaxBufferedBytes ||
           len(r.groups) > fragmentMaxGroups {
            t.Fatal("unbounded reassembly under lossy traffic")
        }
    }
}
