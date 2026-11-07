package pingtunnel

import (
    "bytes"
    "crypto/rand"
    "crypto/hmac"
    "encoding/binary"
    "time"
)

// PTQ4 extends the existing signed PTW4 wake without changing application
// wire v4 or the paired AEAD keys. Its 64-bit random nonce is preserved.
// A separate 8-byte authenticated queue payload reports remote pressure:
//   magic[4] | Unix seconds[8] | nonce[8] | depth[2] |
//   oldestWaitMs[2] | queuedBytes[4] | HMAC-SHA256[0:16].
// The 8-byte metrics segment is masked with a separately domain-separated
// key-derived pad before MAC authentication: observers do not learn queue
// depth or latency. The HMAC uses the existing root-key reverse MAC.
// Only the fixed, pinned foreign peer processes the report. It does not
// authorize a route switch, replay an encrypted frame or carry user data.
const (
    reverseQueueHintBytes=44
    reverseQueueHintSeenLimit=128
)
var reverseQueueHintMagic=[4]byte{'P','T','Q','4'}

// The lower bound is 8 ms = at most 125 adaptive poll opportunities/second.
// Real upstream/downstream DATA may independently trigger ICMP sends.
func reverseQueueHintPollInterval(depth,oldestMs int) time.Duration {
    switch {
    case depth<=0:
        return time.Second
    case depth>=16 || oldestMs>=80:
        return 8*time.Millisecond
    case depth>=6 || oldestMs>=40:
        return 10*time.Millisecond
    case depth>=2 || oldestMs>=20:
        return 12*time.Millisecond
    default:
        return 16*time.Millisecond
    }
}

func saturateToUint16(v int) uint16 {
    if v<=0{return 0}
    if v>=65535{return 65535}
    return uint16(v)
}
func saturateToUint32(v int) uint32 {
    if v<=0{return 0}
    if uint64(v)>=uint64(^uint32(0)){return ^uint32(0)}
    return uint32(v)
}

// Called only after allowBacklogWake has reserved a rate-limited send.
// The snapshot is taken under r.mu but all random and HMAC work occurs
// without the queue lock. Queue age is measured on Iran's clock only.
func (r *reverseTransport) makeQueueHint(now time.Time) ([]byte,error) {
    r.mu.Lock()
    depth:=len(r.pending)
    bytesQueued:=r.pendingBytes
    oldestMs:=0
    selected:=r.selected
    if depth>0 {
        delay:=now.Sub(r.pending[0].created)
        if delay>0 {oldestMs=int(delay/time.Millisecond)}
    }
    r.mu.Unlock()
    if selected!=ICMPReverse || depth==0 {return nil,nil}
    frame:=make([]byte,reverseQueueHintBytes)
    copy(frame[:4],reverseQueueHintMagic[:])
    binary.BigEndian.PutUint64(frame[4:12],uint64(now.Unix()))
    if _,err:=rand.Read(frame[12:20]);err!=nil{return nil,err}
    binary.BigEndian.PutUint16(frame[20:22],saturateToUint16(depth))
    binary.BigEndian.PutUint16(frame[22:24],saturateToUint16(oldestMs))
    binary.BigEndian.PutUint32(frame[24:28],saturateToUint32(bytesQueued))
    // Conceal queue pressure against passive ICMP observers. The fresh
    // 64-bit nonce provides a unique pad; the tag authenticates CIPHERTEXT
    // and all header fields. This never changes application Wire v4.
    masked:=make([]byte,0,len("PTQ4/metadata-mask/v1")+20)
    masked=append(masked,[]byte("PTQ4/metadata-mask/v1")...)
    masked=append(masked,frame[:20]...)
    mask:=r.mac(masked)
    for i:=0;i<8;i++ {frame[20+i]^=mask[i]}
    tag:=r.mac(frame[:28])
    copy(frame[28:],tag[:16])
    return frame,nil
}

// This function never trusts unsigned queue estimates. Prevent replay,
// malformed metadata, stale timestamps and rate-spam independently of
// the encrypted packet anti-replay window and PTR4 switch proofs.
func (r *reverseTransport) authenticateQueueHint(frame []byte,now time.Time) bool {
    if len(frame)!=reverseQueueHintBytes ||
        !bytes.Equal(frame[:4],reverseQueueHintMagic[:]) {return false}
    seconds:=int64(binary.BigEndian.Uint64(frame[4:12]))
    drift:=now.Unix()-seconds
    if drift<0 {drift=-drift}
    if drift>int64(reverseProbeWindow/time.Second){return false}
    tag:=r.mac(frame[:28])
    if !hmac.Equal(frame[28:],tag[:16]){return false}
    masked:=make([]byte,0,len("PTQ4/metadata-mask/v1")+20)
    masked=append(masked,[]byte("PTQ4/metadata-mask/v1")...)
    masked=append(masked,frame[:20]...)
    mask:=r.mac(masked)
    var metadata [8]byte
    copy(metadata[:],frame[20:28])
    for i:=0;i<8;i++ {metadata[i]^=mask[i]}
    depth:=int(binary.BigEndian.Uint16(metadata[0:2]))
    oldestMs:=int(binary.BigEndian.Uint16(metadata[2:4]))
    queuedBytes:=int(binary.BigEndian.Uint32(metadata[4:8]))
    if depth<=0 || depth>reverseQueueMaxFrames ||
        queuedBytes<=0 || queuedBytes>reverseQueueMaxBytes{return false}

    var nonce [8]byte
    copy(nonce[:],frame[12:20])
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.selected!=ICMPReverse {return false}
    if r.queueHintSeen==nil {r.queueHintSeen=make(map[[8]byte]time.Time)}
    for seen,at:=range r.queueHintSeen {
        if now.Sub(at)>reverseProbeWindow || now.Before(at) {
            delete(r.queueHintSeen,seen)
        }
    }
    if _,exists:=r.queueHintSeen[nonce];exists {
        r.queueHintRejected++
        return false
    }
    if len(r.queueHintSeen)>=reverseQueueHintSeenLimit {
        r.queueHintRejected++
        return false
    }
    r.queueHintSeen[nonce]=now
    if !r.queueHintAt.IsZero() && now.Sub(r.queueHintAt)<reverseWakeReceiveCooldown {
        r.queueHintRejected++
        return false
    }
    r.queueHintAt=now
    r.queueHintDepth=depth
    r.queueHintAgeMs=oldestMs
    r.queueHintBytes=queuedBytes
    r.queueHintReceived++
    return true
}
