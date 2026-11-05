package pingtunnel

import (
    "testing"
    "unsafe"
)

// One simulated hour at >160 authenticated packets/second; in production
// each fragmented ICMP DATA segment has its own AEAD replay sequence.
func TestSecureReplayRemainsFixedAfterLongGamingSession(t *testing.T) {
    var r secureReplay
    const packets = uint64(600_000)
    for n := uint64(1); n <= packets; n++ {
        if !r.accept(n) {
            t.Fatalf("fresh sequence %d incorrectly rejected", n)
        }
    }
    if r.highest != packets {
        t.Fatalf("wrong highest sequence: %d", r.highest)
    }
    if got := unsafe.Sizeof(r); got > 256 {
        t.Fatalf("replay state should remain <=256 bytes, got %d", got)
    }
    if r.accept(packets) || r.accept(packets-1) {
        t.Fatal("replayed recent packets accepted")
    }
    if r.accept(packets-1024) {
        t.Fatal("out-of-window packet accepted")
    }
    if !r.accept(packets+5) || !r.accept(packets+4) {
        t.Fatal("in-window out-of-order packets should pass exactly once")
    }
    if r.accept(packets+4) {
        t.Fatal("duplicate out-of-order packet accepted")
    }
}

func TestSecureReplayCrossWordBoundaries(t *testing.T) {
    for _, advance := range []uint64{1, 63, 64, 65, 127, 128, 511, 1023, 1024, 1025, 999999} {
        var r secureReplay
        if r.accept(0) || !r.accept(1) { t.Fatal("invalid initialization") }
        newest := uint64(1) + advance
        if !r.accept(newest) { t.Fatalf("advance %d rejected", advance) }
        if r.accept(newest) { t.Fatalf("duplicate after advance %d accepted", advance) }
        if advance < replayBits {
            // The very first sequence is still within the window, but
            // was already marked seen. The gap immediately above it was not.
            if r.accept(1) { t.Fatal("old previously seen sequence accepted") }
            if advance > 1 && !r.accept(2) { t.Fatalf("missing gap sequence not accepted after advance %d", advance) }
            if advance > 1 && r.accept(2) { t.Fatal("accepted a duplicate gap sequence") }
        } else if r.accept(1) {
            t.Fatalf("old sequence survived window reset after advance %d", advance)
        }
    }
}

// Tests ordering and replay decisions against a small, readable reference
// model including jumps, duplicates and late UDP packets.
func TestSecureReplayAgainstReferenceModel(t *testing.T) {
    var r secureReplay
    var highest uint64
    seen := make(map[uint64]struct{})
    state := uint64(0x9e3779b97f4a7c15)
    nextRandom := func() uint64 {
        state ^= state << 7
        state ^= state >> 9
        state ^= state << 8
        return state
    }
    for i := 0; i < 80_000; i++ {
        random := nextRandom()
        var n uint64
        switch random % 6 {
        case 0: n = highest + 1
        case 1: n = highest + 1 + (random % 1080)
        case 2: n = highest
        case 3: if highest > 0 { n = highest - (random % (minUint64(highest, 1030))) }
        case 4: if highest > 0 { n = highest - (random % (minUint64(highest, 63))) }
        default: n = highest + 1 + (random % 10)
        }
        expected := false
        if n != 0 && (highest == 0 || n > highest || highest-n < replayBits) {
            _, wasSeen := seen[n]
            expected = !wasSeen
        }
        got := r.accept(n)
        if got != expected {
            t.Fatalf("packet %d, seq %d: got=%t expected=%t highest=%d",i,n,got,expected,highest)
        }
        if got {
            seen[n] = struct{}{}
            if n > highest { highest = n }
        }
        // Reference model keeps only the same fixed-size replay horizon.
        if i % 100 == 0 {
            for old := range seen {
                if highest-old >= replayBits { delete(seen,old) }
            }
        }
    }
}

func minUint64(a,b uint64) uint64 {
    if a<b {return a}
    return b
}

func BenchmarkSecureReplayAfterLongSession(b *testing.B) {
    var r secureReplay
    for n := uint64(1); n <= 600_000; n++ { r.accept(n) }
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        if !r.accept(r.highest+1) { b.Fatal("fresh sequence rejected") }
    }
}
