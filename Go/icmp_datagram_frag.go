package pingtunnel

// Application-frame segmentation keeps encrypted ICMP below the IPv4
// fragmentation threshold. Every segment is encrypted separately with the
// existing session AEAD and replay protection. The reassembled plaintext is
// exactly the original serialized MyMsg, preserving the UDP datagram boundary.
//
// Both peers must run a fragment-aware Go core. No unauthenticated fragments
// enter this reassembler: recvICMP calls it only AFTER successful AEAD open.
import (
    "bytes"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "sync"
    "sync/atomic"
    "time"
)

const (
    // 1200 bytes INCLUDING IPv4 and ICMP headers; intentionally below the
    // measured 1476-byte MTU, with margin for common paths and IP options.
    icmpIPv4PacketBudget = 1200
    icmpIPv4HeaderBytes = 20
    icmpEchoHeaderBytes = 8
    secureAEADHeaderBytes = 29
    secureAEADTagBytes = 16
    icmpMaxSecurePlaintext = icmpIPv4PacketBudget - icmpIPv4HeaderBytes -
        icmpEchoHeaderBytes - secureAEADHeaderBytes - secureAEADTagBytes

    fragmentHeaderBytes = 20
    fragmentPayloadBytes = icmpMaxSecurePlaintext - fragmentHeaderBytes
    fragmentMaxOriginalBytes = 70 * 1024
    fragmentMaxParts = 65
    fragmentMaxGroups = 128
    fragmentMaxBufferedBytes = 2 * 1024 * 1024
    fragmentLifetime = 3 * time.Second
    fecParityMaxPerSecond = 24
    fecCompletedCacheLimit = 256
    fragmentFECFlag = uint16(1 << 15)
)
var fragmentMagic = [4]byte{'P', 'T', 'F', '4'}

// Operational counters; these are Go-process-local, never persisted.
var icmpFragmentedDatagrams atomic.Uint64
var icmpReassembledDatagrams atomic.Uint64
var icmpFragmentDropped atomic.Uint64
var icmpFECParitySent atomic.Uint64
var icmpFECRecovered atomic.Uint64

var fecLimiter struct {
    sync.Mutex
    window time.Time
    used int
}

// Rate-limiting parity prevents a lossy ICMP connection from being flooded
// with repair traffic, which could otherwise worsen QUIC jitter.
func allowBoundedFEC(now time.Time) bool {
    fecLimiter.Lock()
    defer fecLimiter.Unlock()
    if fecLimiter.window.IsZero() || now.Before(fecLimiter.window) ||
        now.Sub(fecLimiter.window) >= time.Second {
        fecLimiter.window = now
        fecLimiter.used = 0
    }
    if fecLimiter.used >= fecParityMaxPerSecond { return false }
    fecLimiter.used++
    return true
}

// One extra authenticated XOR parity segment can recover either missing
// data segment from a two-segment UDP datagram. This is never used for TCP.
func appendBoundedUDPParity(parts [][]byte, now time.Time) [][]byte {
    if len(parts) != 2 { return parts }
    if len(parts[0]) < fragmentHeaderBytes || len(parts[1]) < fragmentHeaderBytes {
        return parts
    }
    if !allowBoundedFEC(now) { return parts }
    first, second := parts[0], parts[1]
    parity := make([]byte, fragmentHeaderBytes + fragmentPayloadBytes)
    copy(parity[:fragmentHeaderBytes], first[:fragmentHeaderBytes])
    binary.BigEndian.PutUint16(parity[12:14], 2)
    binary.BigEndian.PutUint16(parity[14:16], fragmentFECFlag | 2)
    for i, b := range first[fragmentHeaderBytes:] {
        parity[fragmentHeaderBytes+i] ^= b
    }
    for i, b := range second[fragmentHeaderBytes:] {
        parity[fragmentHeaderBytes+i] ^= b
    }
    for i, part := range parts {
        copyOfPart := append([]byte(nil), part...)
        binary.BigEndian.PutUint16(copyOfPart[14:16], fragmentFECFlag | 2)
        parts[i] = copyOfPart
    }
    icmpFECParitySent.Add(1)
    return append(parts, parity)
}

// A segment header is inside the authenticated plaintext (never exposed to
// an unauthenticated network peer).
//
//   magic[4] | datagram-ID[8] | fragment-index[2] |
//   fragment-count[2] | original-length[4] | plaintext-chunk...
func splitAuthenticatedMessage(data []byte) ([][]byte, error) {
    if len(data) <= icmpMaxSecurePlaintext {
        return [][]byte{data}, nil
    }
    if len(data) > fragmentMaxOriginalBytes {
        return nil, errors.New("serialized message exceeds safe fragmentation limit")
    }
    count := (len(data) + fragmentPayloadBytes - 1) / fragmentPayloadBytes
    if count < 2 || count > fragmentMaxParts {
        return nil, errors.New("invalid fragment count")
    }
    var id [8]byte
    if _, err := rand.Read(id[:]); err != nil { return nil, err }
    result := make([][]byte, 0, count)
    for index := 0; index < count; index++ {
        start := index * fragmentPayloadBytes
        end := start + fragmentPayloadBytes
        if end > len(data) { end = len(data) }
        fragment := make([]byte, fragmentHeaderBytes + end - start)
        copy(fragment[:4], fragmentMagic[:])
        copy(fragment[4:12], id[:])
        binary.BigEndian.PutUint16(fragment[12:14], uint16(index))
        binary.BigEndian.PutUint16(fragment[14:16], uint16(count))
        binary.BigEndian.PutUint32(fragment[16:20], uint32(len(data)))
        copy(fragment[fragmentHeaderBytes:], data[start:end])
        result = append(result, fragment)
    }
    return result, nil
}

type pendingFragmentMessage struct {
    at time.Time
    total int
    parts [][]byte
    received int
    length int
    reserved int
    parity []byte
    fec bool
}

type authenticatedReassembler struct {
    groups map[[8]byte]*pendingFragmentMessage
    buffered int
    completed map[[8]byte]time.Time
}
func (r *authenticatedReassembler) remove(id [8]byte) {
    if x, ok := r.groups[id]; ok {
        r.buffered -= x.reserved
        delete(r.groups, id)
    }
}
func (r *authenticatedReassembler) prune(now time.Time) {
    for id, finished := range r.completed {
        if now.Before(finished) || now.Sub(finished) >= fragmentLifetime {
            delete(r.completed, id)
        }
    }
    for id, group := range r.groups {
        if now.Sub(group.at) >= fragmentLifetime || now.Before(group.at) {
            r.remove(id)
            icmpFragmentDropped.Add(1)
        }
    }
}
func (r *authenticatedReassembler) rememberComplete(id [8]byte, now time.Time) {
    if r.completed == nil { r.completed = make(map[[8]byte]time.Time) }
    if len(r.completed) >= fecCompletedCacheLimit {
        var oldest [8]byte
        var age time.Time
        found := false
        for key, at := range r.completed {
            if !found || at.Before(age) { oldest,age,found = key,at,true }
        }
        if found { delete(r.completed, oldest) }
    }
    r.completed[id] = now
}
func (r *authenticatedReassembler) oldest() ([8]byte, bool) {
    var id [8]byte
    var t time.Time
    found := false
    for key, value := range r.groups {
        if !found || value.at.Before(t) {
            id, t, found = key, value.at, true
        }
    }
    return id, found
}

// accept must only receive plaintext that has already passed secure AEAD
// authentication. It is intentionally single-receiver scoped.
func (r *authenticatedReassembler) accept(frame []byte, now time.Time) ([]byte, bool) {
    if !bytes.HasPrefix(frame, fragmentMagic[:]) {
        return frame, true
    }
    if len(frame) < fragmentHeaderBytes {
        icmpFragmentDropped.Add(1)
        return nil, false
    }
    var id [8]byte
    copy(id[:], frame[4:12])
    index := int(binary.BigEndian.Uint16(frame[12:14]))
    count := int(binary.BigEndian.Uint16(frame[14:16]))
    total := int(binary.BigEndian.Uint32(frame[16:20]))
    chunk := frame[fragmentHeaderBytes:]
    if count < 2 || count > fragmentMaxParts || index >= count ||
        total <= icmpMaxSecurePlaintext || total > fragmentMaxOriginalBytes ||
        len(chunk) == 0 || len(chunk) > fragmentPayloadBytes ||
        count != (total + fragmentPayloadBytes - 1)/fragmentPayloadBytes {
        icmpFragmentDropped.Add(1)
        return nil, false
    }
    expected := fragmentPayloadBytes
    if index == count-1 { expected = total - index*fragmentPayloadBytes }
    if len(chunk) != expected {
        icmpFragmentDropped.Add(1)
        return nil, false
    }
    if r.groups == nil { r.groups = make(map[[8]byte]*pendingFragmentMessage) }
    r.prune(now)
    group, exists := r.groups[id]
    if exists && (group.total != total || len(group.parts) != count) {
        r.remove(id)
        icmpFragmentDropped.Add(1)
        return nil, false
    }
    if !exists {
        for len(r.groups) >= fragmentMaxGroups ||
            r.buffered + total > fragmentMaxBufferedBytes {
            old, ok := r.oldest()
            if !ok { return nil, false }
            r.remove(old)
            icmpFragmentDropped.Add(1)
        }
        group = &pendingFragmentMessage{at: now, total: total, parts: make([][]byte, count)}
        r.groups[id] = group
        r.buffered += total
    }
    if group.parts[index] != nil {
        // Duplicates cannot overwrite previously authenticated fragments.
        return nil, false
    }
    group.parts[index] = append([]byte(nil), chunk...)
    group.received++
    group.length += len(chunk)
    if group.received < len(group.parts) { return nil, false }
    // All exact-size segments arrived. Reconstruct exactly one original
    // datagram and then release the entire assembly.
    output := make([]byte, 0, total)
    for _, part := range group.parts { output = append(output, part...) }
    r.remove(id)
    if len(output) != total {
        icmpFragmentDropped.Add(1)
        return nil, false
    }
    icmpReassembledDatagrams.Add(1)
    return output, true
}
