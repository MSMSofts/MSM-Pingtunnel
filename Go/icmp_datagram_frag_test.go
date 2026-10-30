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

func TestBoundedFECRecoversEitherMissingSegment(t *testing.T) {
    original := bytes.Repeat([]byte("quic-video-datagram"), 78)
    data, err := splitAuthenticatedMessage(original)
    if err != nil || len(data) != 2 {
        t.Fatalf("test message must have 2 segments: count=%d err=%v",len(data),err)
    }
    // Give this test a clean parity allowance.
    fecLimiter.Lock()
    fecLimiter.window = time.Time{}
    fecLimiter.used = 0
    fecLimiter.Unlock()
    pieces := appendBoundedUDPParity(data, time.Now())
    if len(pieces) != 3 { t.Fatalf("want 2+1 FEC, got %d",len(pieces)) }
    if binary.BigEndian.Uint16(pieces[2][12:14]) != 2 {
        t.Fatal("parity must have index 2")
    }
    for lost := 0; lost < 2; lost++ {
        var reassembler authenticatedReassembler
        now := time.Now()
        var result []byte
        var ok bool
        if lost==0 {
            result,ok = reassembler.accept(pieces[1],now)
        } else {
            result,ok = reassembler.accept(pieces[0],now)
        }
        if ok || result!=nil { t.Fatal("incomplete UDP delivered before parity") }
        result,ok = reassembler.accept(pieces[2],now)
        if !ok || !bytes.Equal(result, original) {
            t.Fatalf("could not reconstruct missing segment %d",lost)
        }
        if after,done := reassembler.accept(pieces[lost],now); done || after!=nil {
            t.Fatal("late fragment replay caused duplicate UDP delivery")
        }
        if reassembler.buffered!=0 || len(reassembler.groups)!=0 {
            t.Fatal("recovered message leaked fragment state")
        }
    }
}
func TestFECWithoutLossDeliversOnceAndIgnoresLateParity(t *testing.T) {
    original := bytes.Repeat([]byte("REELS"), 310)
    pieces, err := splitAuthenticatedMessage(original)
    if err != nil || len(pieces)!=2 { t.Fatal("expected 2 fragments") }
    fecLimiter.Lock()
    fecLimiter.window = time.Time{}
    fecLimiter.used = 0
    fecLimiter.Unlock()
    pieces = appendBoundedUDPParity(pieces,time.Now())
    var r authenticatedReassembler
    now := time.Now()
    if _,ok:=r.accept(pieces[0],now);ok{t.Fatal("early delivery")}
    reconstructed,ok:=r.accept(pieces[1],now)
    if !ok||!bytes.Equal(reconstructed,original){t.Fatal("normal FEC group not delivered")}
    if out,again:=r.accept(pieces[2],now);again||out!=nil{
        t.Fatal("late parity must never start another UDP datagram")
    }
    if len(r.groups)!=0||r.buffered!=0{t.Fatal("late parity allocated a new group")}
}
func TestFECNeverAmplifiesBeyondBoundedRate(t *testing.T) {
    now:=time.Now()
    fecLimiter.Lock()
    fecLimiter.window=time.Time{}
    fecLimiter.used=0
    fecLimiter.Unlock()
    data:=bytes.Repeat([]byte("UDP"),550)
    allowed:=0
    for i:=0;i<fecParityMaxPerSecond+15;i++{
        chunks,err:=splitAuthenticatedMessage(data)
        if err!=nil||len(chunks)!=2{t.Fatal("unexpected chunks")}
        if len(appendBoundedUDPParity(chunks,now))==3 {allowed++}
    }
    if allowed!=fecParityMaxPerSecond{
        t.Fatalf("parity amplified %d packets in one second, expected %d",
            allowed,fecParityMaxPerSecond)
    }
    chunks,_:=splitAuthenticatedMessage(data)
    if len(appendBoundedUDPParity(chunks,now.Add(time.Second)))!=3 {
        t.Fatal("rate allowance not replenished")
    }
}
func TestMalformedAuthenticatedParityIsRejected(t *testing.T) {
    original:=bytes.Repeat([]byte("udp"),700)
    pieces,err:=splitAuthenticatedMessage(original)
    if err!=nil||len(pieces)!=2{t.Fatal("expected pair")}
    fecLimiter.Lock()
    fecLimiter.window=time.Time{}
    fecLimiter.used=0
    fecLimiter.Unlock()
    pieces=appendBoundedUDPParity(pieces,time.Now())
    p:=append([]byte(nil),pieces[2]...)
    binary.BigEndian.PutUint16(p[12:14],3)
    var r authenticatedReassembler
    if _,ok:=r.accept(p,time.Now());ok{t.Fatal("bad parity index accepted")}
    if len(r.groups)!=0{t.Fatal("bad parity consumed group memory")}
    broken:=append([]byte(nil),pieces[1]...)
    broken=broken[:len(broken)-1]
    if _,ok:=r.accept(broken,time.Now());ok{t.Fatal("short segment accepted")}
    if len(r.groups)!=0{t.Fatal("bad length consumed group memory")}
}
