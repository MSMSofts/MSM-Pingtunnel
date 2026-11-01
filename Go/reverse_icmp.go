package pingtunnel

// Reverse ICMP transport primitives. The physical region determines which
// application runs the listener or forwarder; it is NOT the ICMP initiator.
// No unauthenticated probe is permitted to change the selected direction.
import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "bytes"
    "encoding/binary"
    "errors"
    "sort"
    "sync"
    "time"
)

type ICMPDirection string

const (
    ICMPAuto ICMPDirection = "auto"
    ICMPDirect ICMPDirection = "direct"
    ICMPReverse ICMPDirection = "reverse"
)

func ParseICMPDirection(s string) (ICMPDirection, error) {
    switch ICMPDirection(s) {
    case ICMPAuto, ICMPDirect, ICMPReverse:
        return ICMPDirection(s), nil
    default:
        return "", errors.New("icmp_direction must be auto, direct or reverse")
    }
}

const (
    reverseProbeBytes = 36
    reverseProbeWindow = 20 * time.Second
    // The poller can send 500 signed polls/s, retaining roughly 10,000
    // unique nonces inside the 20-second replay window. 4096 rejected
    // otherwise-valid requests every ~8 seconds during active streaming.
    reverseReplayCacheLimit = 16384
    // Sparse side-channel health checks are safe while Direct carries live
    // user traffic: only signed replies prove that Iran's userspace is alive
    // AND that its Echo Reply can reach Foreign.
    reverseDirectProbeInterval = 10 * time.Second
    directBackgroundProbeInterval = 60 * time.Second
    reverseProofMinInterval = 9 * time.Second
    reverseProofTTL = 25 * time.Second
    reverseSwitchRetryCooldown = 3 * time.Minute
    reverseRequiredProofs = 2
    reverseAutoDelay = 0 * time.Second
    // Reverse must be genuinely unavailable before switching direction.
    // A short X25519 delay, an idle session or sporadic ICMP loss is not
    // evidence that the preferred route has failed.
    reverseAbsentGrace = 90 * time.Second
    reverseUnconfirmedGrace = 150 * time.Second
    reverseEstablishedGrace = 150 * time.Second
    reverseMinDwell = 60 * time.Second
    reverseFrameTTL = 12 * time.Second
    reverseQueueMaxFrames = 256
    reverseQueueMaxBytes = 2 * 1024 * 1024
    // Rolling successful Echo Reply send-delay history. Fixed allocation and
    // bounded sorting cost when the once-per-second status snapshot is read.
    reverseDeliveryWindow = 128
    // Track recent outbound encrypted Echo Requests (DATA and PING) to
    // distinguish byte-identical Linux echoes from legitimate peer DATA.
    reverseEchoTrackingWindow = 8 * time.Second
    reverseEchoTrackingCapacity = 16384
)

var reverseProbeMagic = [4]byte{'P','T','R','4'}
var reverseProofMagic = [4]byte{'P','R','A','4'}
var reverseSwitchMagic = [4]byte{'P','T','S','4'}
var directProbeMagic = [4]byte{'P','T','C','4'}
var directProofMagic = [4]byte{'P','D','A','4'}

// The 4-byte ID/sequence pairs are scoped to a 25-second challenge lifetime.
// They are matched against an HMACed nonce; they never change the AEAD keys.
type reverseProbeChallenge struct {
    first20 [20]byte
    sentAt time.Time
}

type reverseQueuedFrame struct {
    data []byte
    created time.Time
}

// A reflected ICMP Echo Reply copies the entire encrypted request payload.
// Matching the whole SHA-256 ciphertext digest AND Echo ID/sequence avoids
// dropping genuine peer DATA just because it also starts with PTD4.
type reverseSentEchoSignature struct {
    id uint16
    seq uint16
    ciphertextDigest [32]byte
}
type reverseEchoKind uint8

const (
    reverseEchoDATA reverseEchoKind = iota
    reverseEchoPING
    reverseEchoOther
)

type reverseSentEchoRecord struct {
    signature reverseSentEchoSignature
    at time.Time
    kind reverseEchoKind
}

func reverseEchoSignature(id, seq int, payload []byte) reverseSentEchoSignature {
    return reverseSentEchoSignature{
        id: uint16(id),
        seq: uint16(seq),
        ciphertextDigest: sha256.Sum256(payload),
    }
}

type reverseTransport struct {
    mu sync.Mutex
    preference ICMPDirection
    selected ICMPDirection
    started time.Time
    lastSwitch time.Time
    lastDemand time.Time
    demandSince time.Time
    fallbackCount uint64
    lastFallbackReason string
    secret [32]byte
    pending []reverseQueuedFrame
    pendingBytes int
    drops uint64
    recent map[[8]byte]time.Time
    lastPrune time.Time
    replayCapacityRejects uint64
    lastValidProbe time.Time
    probeChallenges map[uint32]reverseProbeChallenge
    directProbeChallenges map[uint32]reverseProbeChallenge
    lastDirectProbe time.Time
    lastDirectProof time.Time
    directProbeChecks uint64
    directPathProofs uint64
    lastProofSent time.Time
    lastProofAt time.Time
    proofConfirmations int
    lastSwitchAttempt time.Time
    reverseProofs uint64
    reverseSwitchAttempts uint64
    pollRequests uint64
    pollsSkippedByData uint64
    lastUsefulFrame time.Time
    usefulBurst int
    lastOutboundData time.Time
    outboundBurst int
    lastDeliveredQueueDelayMs int64
    maxDeliveredQueueDelayMs int64
    deliveredFrames uint64
    delayedFrames uint64
    veryDelayedFrames uint64
    deliveryDelaySamples [reverseDeliveryWindow]uint32
    deliveryDelaySampleCount int
    deliveryDelaySampleNext int
    lastReceiveAck time.Time
    failedReplies uint64
    reflectedPolls uint64
    reflectedDataEchoes uint64
    reflectedPingEchoes uint64
    reflectedOtherEchoes uint64
    expiredEchoSignatures uint64
    capacityEvictedEchoSignatures uint64
    // The ring is chronological, bounded, and contains no ciphertext.
    // A head/tail cursor lets us prune expired signatures in O(1)
    // amortized time instead of retaining dead entries until wraparound.
    outboundEchoes map[reverseSentEchoSignature]reverseSentEchoRecord
    outboundEchoRing [reverseEchoTrackingCapacity]reverseSentEchoRecord
    outboundEchoHead int
    outboundEchoCount int
    pollPeriodMillis int
    queuePeak int
}

func newReverseTransport(preference ICMPDirection, key []byte, now time.Time) (*reverseTransport, error) {
    if len(key)!=32 {return nil, errors.New("reverse transport requires a 32-byte shared pairing key")}
    if _,err:=ParseICMPDirection(string(preference));err!=nil{return nil,err}
    r:=&reverseTransport{preference:preference,selected:ICMPReverse,started:now}
    copy(r.secret[:],key)
    if preference==ICMPDirect {r.selected=ICMPDirect}
    return r,nil
}

func (r *reverseTransport) noteDemand(now time.Time,hasTraffic bool) {
 r.mu.Lock();defer r.mu.Unlock()
 if !hasTraffic {
     // Preserve the last demand timestamp for the short activity grace period,
     // but close the sustained-demand window for a later retry.
     r.demandSince=time.Time{}
     return
 }
 if r.lastDemand.IsZero() || now.Sub(r.lastDemand)>5*time.Second || r.demandSince.IsZero() {
     r.demandSince=now
 }
 r.lastDemand=now
}

// A stale link alone does not trigger disruption of a quiet direct session.
// The local client must have recently requested actual transport service.
func (r *reverseTransport) acceptReverseOnDemand(now time.Time,lastAuthenticated time.Time) bool {
 r.mu.Lock();defer r.mu.Unlock()
 if r.preference==ICMPDirect{return false}
 if r.selected==ICMPReverse{return true}
 if r.preference==ICMPReverse{return true}
 if r.lastDemand.IsZero()||now.Sub(r.lastDemand)>30*time.Second{return false}
 return lastAuthenticated.IsZero()||now.Sub(lastAuthenticated)>=35*time.Second
}

func (r *reverseTransport) direction() ICMPDirection {
    r.mu.Lock();defer r.mu.Unlock()
    return r.selected
}

// Fall back only when explicitly requested by the authenticated link
// coordinator. Path switching is bounded by a minimum dwell interval.
func (r *reverseTransport) choose(direction ICMPDirection, now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if direction!=ICMPDirect && direction!=ICMPReverse{return false}
    if r.preference!=ICMPAuto && direction!=r.preference{return false}
    if r.selected==direction{return false}
    if !r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell{return false}
    r.selected=direction
    r.lastSwitch=now
    r.proofConfirmations=0
    r.lastProofAt=time.Time{}
    r.probeChallenges=nil
    // Queued ciphertext cannot survive a transport/session change. Account
    // for discarded frames explicitly instead of silently losing them.
    r.drops+=uint64(len(r.pending))
    r.pending=nil
    r.pendingBytes=0
    return true
}

// Reverse is the preferred route. Direct is permitted only after sustained
// *local user demand* and independently observed reverse-path failure.
// The authenticated reverse polls are important: an idle AEAD session can
// legitimately have no DATA for many minutes while the route stays healthy.
func (r *reverseTransport) fallbackDirect(now time.Time, ready bool, lastAuthenticated time.Time) bool {
 r.mu.Lock()
 reference:=r.started
 if !r.lastSwitch.IsZero(){reference=r.lastSwitch}
 elapsed:=now.Sub(reference)
 demandDuration:=now.Sub(r.demandSince)
 activeDemand:=!r.demandSince.IsZero() &&
   !r.lastDemand.IsZero() && now.Sub(r.lastDemand)<=5*time.Second
 probeAge:=time.Duration(1<<63-1)
 if !r.lastValidProbe.IsZero(){probeAge=now.Sub(r.lastValidProbe)}
 authenticatedAge:=time.Duration(1<<63-1)
 if !lastAuthenticated.IsZero(){authenticatedAge=now.Sub(lastAuthenticated)}
 allowed:=false
 reason:=""
 if r.preference==ICMPAuto && r.selected==ICMPReverse && activeDemand {
     if ready {
         // Authenticated Reverse polls verify only Foreign -> Iran Echo
         // REQUEST delivery. They do not prove our Echo REPLIES or encrypted
         // DATA reach Foreign. Under sustained real local demand and after
         // a prolonged lack of ANY authenticated two-way data, allow the
         // Direct recovery path even when signed polls still arrive.
         // Without real application demand the route remains unchanged.
         if elapsed>=reverseEstablishedGrace && demandDuration>=reverseAbsentGrace &&
           authenticatedAge>=reverseEstablishedGrace {
             allowed=true
             reason="no_authenticated_reverse_feedback"
         }
     } else if r.lastValidProbe.IsZero() || probeAge>=reverseAbsentGrace {
         // No authenticated probes at all despite prolonged live demand:
         // the overseas -> Iran request path is most likely unavailable.
         if elapsed>=reverseAbsentGrace && demandDuration>=reverseAbsentGrace {
             allowed=true
             reason="reverse_polls_unreachable"
         }
     } else if elapsed>=reverseUnconfirmedGrace && demandDuration>=reverseUnconfirmedGrace {
         // The poll path works, but the four-step authenticated exchange has
         // failed continuously. The reverse reply/control path may be broken.
         allowed=true
         reason="reverse_handshake_unconfirmed"
     }
 }
 r.mu.Unlock()
 if !allowed || !r.choose(ICMPDirect,now){return false}
 r.mu.Lock()
 r.fallbackCount++
 r.lastFallbackReason=reason
 r.mu.Unlock()
 return true
}

// A recent successful direct exchange wins over speculative reverse polls.
// Give the fallback a full stabilization window before trying Reverse again.
func (r *reverseTransport) allowReverseCandidate(now time.Time,ready bool,lastAuthenticated time.Time) bool {
 r.mu.Lock()
 defer r.mu.Unlock()
 if r.preference==ICMPDirect {return false}
 if r.selected==ICMPReverse {return true}
 if !r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell {return false}
 if !ready {return true}
 if r.lastDemand.IsZero() || now.Sub(r.lastDemand)>30*time.Second{return false}
 return lastAuthenticated.IsZero() || now.Sub(lastAuthenticated)>=35*time.Second
}

func (r *reverseTransport) needsProbe(now time.Time, authenticated bool) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference==ICMPDirect{return false}
    if r.selected==ICMPReverse{return true}
    // Always recheck the preferred path on a bounded 10-second schedule,
    // even while authenticated Direct is healthy. A poll itself cannot
    // cause a switch: the paired Go worker must prove the RETURN path.
    return r.preference==ICMPAuto
}

func (r *reverseTransport) mac(body []byte) [32]byte {
    mac:=hmac.New(sha256.New,r.secret[:])
    _,_=mac.Write([]byte("MSM-Pingtunnel/reverse-icmp-poll/v4"))
    _,_=mac.Write(body)
    var tag [32]byte
    copy(tag[:],mac.Sum(nil))
    return tag
}

// A bounded, authenticated probe prevents unauthenticated ICMP scans from
// triggering a reverse handshake. It carries no application plaintext.
func (r *reverseTransport) makeProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,reverseProbeMagic)
}
func (r *reverseTransport) makeSwitchProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,reverseSwitchMagic)
}
func (r *reverseTransport) makeDirectProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,directProbeMagic)
}
func (r *reverseTransport) makeProbeType(now time.Time,magic [4]byte) ([]byte,error) {
    b:=make([]byte,reverseProbeBytes)
    copy(b[:4],magic[:])
    binary.BigEndian.PutUint64(b[4:12],uint64(now.Unix()))
    if _,err:=rand.Read(b[12:20]);err!=nil{return nil,err}
    tag:=r.mac(b[:20])
    copy(b[20:],tag[:16])
    return b,nil
}

// authenticateProbe is replay-limited and tolerant of modest clock skew.
// Caller must verify the configured remote IP before invoking it.
func (r *reverseTransport) authenticateProbe(frame []byte,now time.Time) bool {
    valid,_:=r.authenticateProbeWithSwitch(frame,now)
    return valid
}
func (r *reverseTransport) authenticateDirectProbe(frame []byte,now time.Time) bool {
    if len(frame)!=reverseProbeBytes || !bytes.Equal(frame[:4],directProbeMagic[:]){return false}
    valid,_:=r.authenticateProbeWithSwitch(frame,now)
    return valid
}
func (r *reverseTransport) authenticateProbeWithSwitch(frame []byte,now time.Time) (valid,switchRequest bool) {
    if len(frame)!=reverseProbeBytes{return false,false}
    isProbe:=bytes.Equal(frame[:4],reverseProbeMagic[:])
    isSwitch:=bytes.Equal(frame[:4],reverseSwitchMagic[:])
    isDirect:=bytes.Equal(frame[:4],directProbeMagic[:])
    if !isProbe && !isSwitch && !isDirect{return false,false}
    seconds:=int64(binary.BigEndian.Uint64(frame[4:12]))
    delta:=now.Unix()-seconds
    if delta<0 {delta=-delta}
    if delta>int64(reverseProbeWindow.Seconds()){return false,false}
    tag:=r.mac(frame[:20])
    if !hmac.Equal(frame[20:36],tag[:16]){return false,false}
    var nonce [8]byte
    copy(nonce[:],frame[12:20])
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.recent==nil{r.recent=make(map[[8]byte]time.Time)}
    if _,ok:=r.recent[nonce];ok{return false,false}
    if r.lastPrune.IsZero() || now.Sub(r.lastPrune)>=time.Second {
        for id,t:=range r.recent {
            if now.Sub(t)>reverseProbeWindow{delete(r.recent,id)}
        }
        r.lastPrune=now
    }
    // Capacity accommodates max intended poll rate plus jitter/bursts;
    // never disable replay tracking just to meet throughput.
    if len(r.recent)>=reverseReplayCacheLimit {
        r.replayCapacityRejects++
        return false,false
    }
    r.recent[nonce]=now
    if !isDirect{r.lastValidProbe=now}
    return true,isSwitch
}

// Only a matched, one-time, MAC-authenticated userspace Echo Reply proves
// that the Reverse route has recovered while Direct is still active.
func (r *reverseTransport) makeProof(probe []byte) []byte {
    if len(probe)!=reverseProbeBytes{return nil}
    reply:=append([]byte(nil),probe...)
    copy(reply[:4],reverseProofMagic[:])
    tag:=r.mac(reply[:20])
    copy(reply[20:],tag[:16])
    return reply
}
func (r *reverseTransport) makeDirectProof(probe []byte) []byte {
    if len(probe)!=reverseProbeBytes{return nil}
    reply:=append([]byte(nil),probe...)
    copy(reply[:4],directProofMagic[:])
    tag:=r.mac(reply[:20])
    copy(reply[20:],tag[:16])
    return reply
}
// Low-rate, authenticated Direct reachability check; it never selects
// Direct or resets the preferred Reverse session while healthy.
func (r *reverseTransport) shouldProbeDirect(now time.Time,ready bool) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPReverse || !ready{return false}
    if !r.lastDirectProbe.IsZero() && now.Sub(r.lastDirectProbe)<directBackgroundProbeInterval{return false}
    r.lastDirectProbe=now
    r.directProbeChecks++
    return true
}
func (r *reverseTransport) stageDirectProbe(id,seq int,probe []byte,now time.Time) {
    if len(probe)!=reverseProbeBytes{return}
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPReverse{return}
    if r.directProbeChallenges==nil{
        r.directProbeChallenges=make(map[uint32]reverseProbeChallenge)
    }
    for key,ch:=range r.directProbeChallenges{
        if now.Sub(ch.sentAt)>reverseProofTTL{delete(r.directProbeChallenges,key)}
    }
    if len(r.directProbeChallenges)>=8{
        for key:=range r.directProbeChallenges{delete(r.directProbeChallenges,key);break}
    }
    var prefix [20]byte
    copy(prefix[:],probe[:20])
    r.directProbeChallenges[probeChallengeKey(id,seq)]=reverseProbeChallenge{first20:prefix,sentAt:now}
}
func (r *reverseTransport) cancelDirectProbe(id,seq int){
    r.mu.Lock();delete(r.directProbeChallenges,probeChallengeKey(id,seq));r.mu.Unlock()
}
func (r *reverseTransport) acceptDirectProof(id,seq int,reply []byte,now time.Time) bool {
    if len(reply)!=reverseProbeBytes||!bytes.Equal(reply[:4],directProofMagic[:]){return false}
    mac:=r.mac(reply[:20])
    if !hmac.Equal(reply[20:],mac[:16]){return false}
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPReverse{return false}
    key:=probeChallengeKey(id,seq)
    challenge,ok:=r.directProbeChallenges[key]
    if !ok || now.Before(challenge.sentAt)||now.Sub(challenge.sentAt)>reverseProofTTL{return false}
    if !hmac.Equal(reply[4:20],challenge.first20[4:20]){return false}
    delete(r.directProbeChallenges,key)
    r.directPathProofs++
    r.lastDirectProof=now
    return true
}
func (r *reverseTransport) allowDirectPathProof(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPDirect{return false}
    if !r.lastProofSent.IsZero() && now.Sub(r.lastProofSent)<reverseProofMinInterval{return false}
    r.lastProofSent=now
    return true
}
func probeChallengeKey(id,seq int)uint32{
    return uint32(uint16(id))<<16 | uint32(uint16(seq))
}
func (r *reverseTransport) stageProbe(id,seq int,probe []byte,now time.Time) {
    if len(probe)!=reverseProbeBytes{return}
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPDirect{return}
    if r.probeChallenges==nil{r.probeChallenges=make(map[uint32]reverseProbeChallenge)}
    for k,c:=range r.probeChallenges{
        if now.Sub(c.sentAt)>reverseProofTTL{delete(r.probeChallenges,k)}
    }
    // At most three live challenges at the default one-per-10s cadence.
    // Cap strictly even if a scheduling bug or malformed clock is observed.
    if len(r.probeChallenges)>=8{
        for k:=range r.probeChallenges{delete(r.probeChallenges,k);break}
    }
    var prefix [20]byte
    copy(prefix[:],probe[:20])
    r.probeChallenges[probeChallengeKey(id,seq)]=reverseProbeChallenge{first20:prefix,sentAt:now}
}
func (r *reverseTransport) cancelProbe(id,seq int){
    r.mu.Lock();delete(r.probeChallenges,probeChallengeKey(id,seq));r.mu.Unlock()
}
func (r *reverseTransport) acceptProof(id,seq int,reply []byte,now time.Time) bool {
    if len(reply)!=reverseProbeBytes || !bytes.Equal(reply[:4],reverseProofMagic[:]){return false}
    mac:=r.mac(reply[:20])
    if !hmac.Equal(reply[20:],mac[:16]){return false}
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPDirect{return false}
    key:=probeChallengeKey(id,seq)
    challenge,ok:=r.probeChallenges[key]
    if !ok || now.Before(challenge.sentAt) || now.Sub(challenge.sentAt)>reverseProofTTL {
        return false
    }
    if !hmac.Equal(reply[4:20],challenge.first20[4:20]){return false}
    delete(r.probeChallenges,key)
    if r.lastProofAt.IsZero() || now.Sub(r.lastProofAt)>reverseProofTTL {
        r.proofConfirmations=0
    }
    if !r.lastProofAt.IsZero() && now.Sub(r.lastProofAt)<5*time.Second{return false}
    if r.proofConfirmations<reverseRequiredProofs{r.proofConfirmations++}
    r.lastProofAt=now
    r.reverseProofs++
    return true
}
// Call on the foreign poller only, after two separate successful proofs.
// Never reset the healthy Direct AEAD session merely due to a timer.
func (r *reverseTransport) takeSwitchRequest(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAuto || r.selected!=ICMPDirect ||
        r.proofConfirmations<reverseRequiredProofs ||
        r.lastProofAt.IsZero() || now.Sub(r.lastProofAt)>reverseProofTTL ||
        (!r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell) ||
        (!r.lastSwitchAttempt.IsZero() && now.Sub(r.lastSwitchAttempt)<reverseSwitchRetryCooldown) {
        return false
    }
    r.lastSwitchAttempt=now
    r.reverseSwitchAttempts++
    r.proofConfirmations=0
    return true
}
func (r *reverseTransport) notePollSent(){
    r.mu.Lock();r.pollRequests++;r.mu.Unlock()
}
func (r *reverseTransport) notePollSkippedByData(){
    r.mu.Lock();r.pollsSkippedByData++;r.mu.Unlock()
}
// A legitimate outbound encrypted foreign DATA Echo Request already gives
// Iran an opportunity to send one queued Echo Reply. Do not add a synthetic
// poll in the same small time window.
func (r *reverseTransport) recentOutboundData(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    return r.selected==ICMPReverse && !r.lastOutboundData.IsZero() &&
        now.Sub(r.lastOutboundData)>=0 && now.Sub(r.lastOutboundData)<20*time.Millisecond
}


func (r *reverseTransport) enqueue(frame []byte,now time.Time) bool {
    if len(frame)==0 || len(frame)>10240{return false}
    r.mu.Lock();defer r.mu.Unlock()
    for len(r.pending)>0 && (len(r.pending)>=reverseQueueMaxFrames || r.pendingBytes+len(frame)>reverseQueueMaxBytes){
        r.pendingBytes-=len(r.pending[0].data)
        r.pending[0]=reverseQueuedFrame{}
        r.pending=r.pending[1:]
        r.drops++
    }
    r.pending=append(r.pending,reverseQueuedFrame{data:append([]byte(nil),frame...),created:now})
    r.pendingBytes+=len(frame)
    if len(r.pending)>r.queuePeak{r.queuePeak=len(r.pending)}
    return true
}

func (r *reverseTransport) takeFrame(now time.Time) (reverseQueuedFrame,bool) {
    r.mu.Lock();defer r.mu.Unlock()
    for len(r.pending)>0{
        f:=r.pending[0]
        r.pending[0]=reverseQueuedFrame{}
        r.pending=r.pending[1:]
        r.pendingBytes-=len(f.data)
        if now.Sub(f.created)>reverseFrameTTL{r.drops++;continue}
        return f,true
    }
    return reverseQueuedFrame{},false
}
func (r *reverseTransport) take(now time.Time) []byte {
    f,ok:=r.takeFrame(now)
    if !ok{return nil}
    return f.data
}
// Roll a failed socket write back to the head of the queue. Preserve the
// original enqueue timestamp so repeated failures never extend its lifetime.
func (r *reverseTransport) restoreFront(f reverseQueuedFrame,now time.Time) {
    if len(f.data)==0{return}
    r.mu.Lock();defer r.mu.Unlock()
    if now.Sub(f.created)>reverseFrameTTL{r.drops++;return}
    for len(r.pending)>0 && (len(r.pending)>=reverseQueueMaxFrames ||
        r.pendingBytes+len(f.data)>reverseQueueMaxBytes){
        last:=len(r.pending)-1
        r.pendingBytes-=len(r.pending[last].data)
        r.pending[last]=reverseQueuedFrame{}
        r.pending=r.pending[:last]
        r.drops++
    }
    r.pending=append(r.pending,reverseQueuedFrame{})
    copy(r.pending[1:],r.pending[:len(r.pending)-1])
    r.pending[0]=f
    r.pendingBytes+=len(f.data)
    r.failedReplies++
}
// Confirm that the foreign server received authenticated Iran-side data.
 // The normal ICMP poll alone proves only the inbound request path.
func (r *reverseTransport) shouldSendReceiveAck(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.lastUsefulFrame.IsZero() || now.Sub(r.lastUsefulFrame)<0 ||
        now.Sub(r.lastUsefulFrame)>10*time.Second {
        return false
    }
    if !r.lastReceiveAck.IsZero() && now.Sub(r.lastReceiveAck)<8*time.Second {
        return false
    }
    r.lastReceiveAck=now
    return true
}
// Count only echo reflections delivered to the Go receive path. This
// separates harmless kernel ICMP traffic from AEAD authentication failures.
func (r *reverseTransport) noteReflectedProbe() {
    r.mu.Lock()
    r.reflectedPolls++
    r.mu.Unlock()
}

// A peer may reflect an encrypted Echo Request without carrying any new
// authenticated payload. Prune chronological tracking entries, including
// canceled writes, whenever a send, receive or status snapshot touches this
// cache. This keeps the map empty after eight seconds of real inactivity.
func (r *reverseTransport) pruneOutboundEchoesLocked(now time.Time) {
    for r.outboundEchoCount>0 {
        record:=r.outboundEchoRing[r.outboundEchoHead]
        active,ok:=r.outboundEchoes[record.signature]
        expired:=!now.Before(record.at) && now.Sub(record.at)>reverseEchoTrackingWindow
        // A canceled or replaced record at the head can be reclaimed at
        // once, without blocking later entries.
        if ok && active.at.Equal(record.at) && !expired {break}
        if ok && active.at.Equal(record.at) {
            delete(r.outboundEchoes,record.signature)
            if expired {r.expiredEchoSignatures++}
        }
        r.outboundEchoRing[r.outboundEchoHead]=reverseSentEchoRecord{}
        r.outboundEchoHead=(r.outboundEchoHead+1)%reverseEchoTrackingCapacity
        r.outboundEchoCount--
    }
}

// Stage BEFORE socket WriteTo: the Linux echo may be delivered before the
// write returns. Do not retain plaintext, only a full-ciphertext SHA-256
// digest with the original ICMP Echo ID and sequence.
func (r *reverseTransport) stageOutboundEcho(id,seq int,payload []byte,kind reverseEchoKind,now time.Time) (reverseSentEchoSignature,time.Time) {
    key:=reverseEchoSignature(id,seq,payload)
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.outboundEchoes==nil {
        r.outboundEchoes=make(map[reverseSentEchoSignature]reverseSentEchoRecord)
    }
    // Concurrent sends can acquire the lock in a different order from their
    // timestamp capture. Keep the FIFO timestamps monotone for safe expiry.
    if r.outboundEchoCount>0 {
        last:=r.outboundEchoRing[(r.outboundEchoHead+r.outboundEchoCount-1)%reverseEchoTrackingCapacity]
        if now.Before(last.at) {now=last.at}
    }
    r.pruneOutboundEchoesLocked(now)
    if r.outboundEchoCount==reverseEchoTrackingCapacity {
        old:=r.outboundEchoRing[r.outboundEchoHead]
        if current,ok:=r.outboundEchoes[old.signature];ok && current.at.Equal(old.at) {
            delete(r.outboundEchoes,old.signature)
            r.capacityEvictedEchoSignatures++
        }
        r.outboundEchoRing[r.outboundEchoHead]=reverseSentEchoRecord{}
        r.outboundEchoHead=(r.outboundEchoHead+1)%reverseEchoTrackingCapacity
        r.outboundEchoCount--
    }
    record:=reverseSentEchoRecord{signature:key,at:now,kind:kind}
    slot:=(r.outboundEchoHead+r.outboundEchoCount)%reverseEchoTrackingCapacity
    r.outboundEchoRing[slot]=record
    r.outboundEchoCount++
    r.outboundEchoes[key]=record
    return key,now
}

// Keep narrow helpers used by existing DATA regression tests.
func (r *reverseTransport) stageOutboundDataEcho(id,seq int,payload []byte,now time.Time) (reverseSentEchoSignature,time.Time) {
    return r.stageOutboundEcho(id,seq,payload,reverseEchoDATA,now)
}

func (r *reverseTransport) cancelOutboundDataEcho(key reverseSentEchoSignature,at time.Time) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if record,ok:=r.outboundEchoes[key];ok && record.at.Equal(at) {
        delete(r.outboundEchoes,key)
    }
}

// Filter only an exact reflection of a recent foreign-origin encrypted
// request. The current Iran->Foreign AEAD has independent direction keys;
// real ACK frames must not be discarded based on the PTD4 prefix alone.
func (r *reverseTransport) filterReflectedDataEcho(id,seq int,payload []byte,now time.Time) bool {
    key:=reverseEchoSignature(id,seq,payload)
    r.mu.Lock()
    defer r.mu.Unlock()
    r.pruneOutboundEchoesLocked(now)
    record,ok:=r.outboundEchoes[key]
    if !ok || now.Before(record.at) || now.Sub(record.at)>reverseEchoTrackingWindow {
        return false
    }
    switch record.kind {
    case reverseEchoDATA: r.reflectedDataEchoes++
    case reverseEchoPING: r.reflectedPingEchoes++
    default: r.reflectedOtherEchoes++
    }
    return true
}
func (r *reverseTransport) recordPollInterval(period time.Duration) {
    r.mu.Lock();defer r.mu.Unlock()
    r.pollPeriodMillis=int(period/time.Millisecond)
}
func (r *reverseTransport) noteUsefulFrame(now time.Time) {
    r.mu.Lock();defer r.mu.Unlock()
    if !r.lastUsefulFrame.IsZero() && now.Sub(r.lastUsefulFrame)>=0 &&
        now.Sub(r.lastUsefulFrame)<350*time.Millisecond {
        if r.usefulBurst<1024{r.usefulBurst++}
    }else{
        r.usefulBurst=1
    }
    r.lastUsefulFrame=now
}
// noteOutboundFrame records encrypted application DATA sent by the overseas
// endpoint towards Iran. Streaming video is primarily Foreign -> Iran;
// restricting fast polling to inbound ACKs otherwise creates an ACK starvation
// feedback loop. Only genuine DATA, never empty polls, speeds up the poller.
func (r *reverseTransport) noteOutboundFrame(now time.Time) {
    r.mu.Lock();defer r.mu.Unlock()
    if !r.lastOutboundData.IsZero() && now.Sub(r.lastOutboundData)>=0 &&
        now.Sub(r.lastOutboundData)<400*time.Millisecond {
        if r.outboundBurst<1024{r.outboundBurst++}
    } else {
        r.outboundBurst=1
    }
    r.lastOutboundData=now
}
func (r *reverseTransport) pollPeriod(now time.Time,activeConns int,ready bool) time.Duration {
    r.mu.Lock();defer r.mu.Unlock()
    period:=time.Second
    if !ready {
        period=500*time.Millisecond
    } else {
        // Under BBR/QUIC, a short application pause is not an idle
        // connection: ACKs and loss-recovery packets still need return
        // polling. Keep the previously authenticated burst warm for a
        // bounded jitter window; never run at the old 2ms rate solely because a socket
        // remains open.
        if activeConns>0 {period=40*time.Millisecond}
        ageIn:=now.Sub(r.lastUsefulFrame)
        if !r.lastUsefulFrame.IsZero() && ageIn>=0 {
            switch {
            case r.usefulBurst>=4 && ageIn<2400*time.Millisecond:
                period=10*time.Millisecond
            case r.usefulBurst>=2 && ageIn<4500*time.Millisecond:
                if period>16*time.Millisecond {period=16*time.Millisecond}
            case ageIn<4500*time.Millisecond:
                if period>25*time.Millisecond {period=25*time.Millisecond}
            }
        }
        ageOut:=now.Sub(r.lastOutboundData)
        if !r.lastOutboundData.IsZero() && ageOut>=0 {
            switch {
            case r.outboundBurst>=4 && ageOut<4500*time.Millisecond:
                if period>12*time.Millisecond {period=12*time.Millisecond}
            case ageOut<8*time.Second:
                if period>25*time.Millisecond {period=25*time.Millisecond}
            }
        }
    }
    r.pollPeriodMillis=int(period/time.Millisecond)
    return period
}
// Record only a successful Echo Reply send; expired, dropped or failed writes
// must not pretend to represent end-to-end queue progress.
func (r *reverseTransport) noteDeliveredFrame(created,now time.Time) {
    delay:=now.Sub(created)
    if delay<0{delay=0}
    ms:=int64(delay/time.Millisecond)
    r.mu.Lock();defer r.mu.Unlock()
    r.deliveredFrames++
    r.lastDeliveredQueueDelayMs=ms
    if ms>r.maxDeliveredQueueDelayMs {r.maxDeliveredQueueDelayMs=ms}
    if delay>=250*time.Millisecond {r.delayedFrames++}
    if delay>=time.Second {r.veryDelayedFrames++}
    // A rolling distribution is more useful for intermittent video stalls
    // than a maximum from hours ago. Exclude failed socket writes and
    // never refresh the original enqueue time when retrying.
    r.deliveryDelaySamples[r.deliveryDelaySampleNext]=uint32(ms)
    r.deliveryDelaySampleNext=(r.deliveryDelaySampleNext+1)%reverseDeliveryWindow
    if r.deliveryDelaySampleCount<reverseDeliveryWindow {r.deliveryDelaySampleCount++}
}

func (r *reverseTransport) queueDelaySummaryLocked() (average,p95 int64) {
    n:=r.deliveryDelaySampleCount
    if n==0{return 0,0}
    samples:=make([]uint32,n)
    copy(samples,r.deliveryDelaySamples[:n])
    var sum uint64
    for _,v:=range samples {sum+=uint64(v)}
    sort.Slice(samples,func(i,j int)bool{return samples[i]<samples[j]})
    return int64(sum/uint64(n)),int64(samples[(n*95+99)/100-1])
}
type reverseDiagnostics struct {
    Pending int
    PendingBytes int
    QueuePeak int
    QueueDrops uint64
    FailedReplies uint64
    ReflectedPolls uint64
    ReflectedDataEchoes uint64
    ReflectedPingEchoes uint64
    ReflectedOtherEchoes uint64
    OutboundEchoCacheEntries int
    ExpiredEchoSignatures uint64
    CapacityEvictedEchoSignatures uint64
    ReplayCapacityRejects uint64
    PollIntervalMillis int
    ReverseProofs uint64
    ReverseSwitchAttempts uint64
    PollRequests uint64
    PollsSkippedByData uint64
    DirectProbeChecks uint64
    DirectPathProofs uint64
    DirectLastProofAgeSeconds int64
    LastSwitchAgeSeconds int64
    LastUsefulFrameAgeSeconds int64
    FallbackCount uint64
    FallbackReason string
    OldestQueueAgeMs int64
    LastQueueDelayMs int64
    MaxQueueDelayMs int64
    DeliveredFrames uint64
    DelayedFrames uint64
    VeryDelayedFrames uint64
    MeanQueueDelayMs int64
    P95QueueDelayMs int64
    DeliveryDelaySampleCount int
    LastOutboundDataAgeMs int64
}
func (r *reverseTransport) diagnostics(now time.Time)reverseDiagnostics {
    r.mu.Lock();defer r.mu.Unlock()
    r.pruneOutboundEchoesLocked(now)
    age:=int64(-1)
    if !r.lastUsefulFrame.IsZero() {age=int64(now.Sub(r.lastUsefulFrame).Seconds());if age<0{age=0}}
    oldest:=int64(0)
    if len(r.pending)>0 {
        d:=now.Sub(r.pending[0].created)
        if d>0{oldest=int64(d/time.Millisecond)}
    }
    outboundAge:=int64(-1)
    if !r.lastOutboundData.IsZero() {
        d:=now.Sub(r.lastOutboundData)
        if d<0{d=0}
        outboundAge=int64(d/time.Millisecond)
    }
    avgDelay,p95Delay:=r.queueDelaySummaryLocked()
    directProofAge:=int64(-1)
    if !r.lastDirectProof.IsZero(){
        directProofAge=int64(now.Sub(r.lastDirectProof).Seconds())
        if directProofAge<0{directProofAge=0}
    }
    switchAge:=int64(-1)
    if !r.lastSwitch.IsZero(){
        switchAge=int64(now.Sub(r.lastSwitch).Seconds())
        if switchAge<0{switchAge=0}
    }
    return reverseDiagnostics{Pending:len(r.pending),PendingBytes:r.pendingBytes,
        QueuePeak:r.queuePeak,QueueDrops:r.drops,FailedReplies:r.failedReplies,
        ReflectedPolls:r.reflectedPolls,
        ReflectedDataEchoes:r.reflectedDataEchoes,
        ReflectedPingEchoes:r.reflectedPingEchoes,
        ReflectedOtherEchoes:r.reflectedOtherEchoes,
        OutboundEchoCacheEntries:len(r.outboundEchoes),
        ExpiredEchoSignatures:r.expiredEchoSignatures,
        CapacityEvictedEchoSignatures:r.capacityEvictedEchoSignatures,
        ReplayCapacityRejects:r.replayCapacityRejects,
        PollIntervalMillis:r.pollPeriodMillis,LastUsefulFrameAgeSeconds:age,
        ReverseProofs:r.reverseProofs,ReverseSwitchAttempts:r.reverseSwitchAttempts,
        PollRequests:r.pollRequests,PollsSkippedByData:r.pollsSkippedByData,
        DirectProbeChecks:r.directProbeChecks,DirectPathProofs:r.directPathProofs,
        DirectLastProofAgeSeconds:directProofAge,
        LastSwitchAgeSeconds:switchAge,
        FallbackCount:r.fallbackCount,FallbackReason:r.lastFallbackReason,
        OldestQueueAgeMs:oldest,LastQueueDelayMs:r.lastDeliveredQueueDelayMs,
        MaxQueueDelayMs:r.maxDeliveredQueueDelayMs,DeliveredFrames:r.deliveredFrames,
        DelayedFrames:r.delayedFrames,VeryDelayedFrames:r.veryDelayedFrames,
        MeanQueueDelayMs:avgDelay,P95QueueDelayMs:p95Delay,
        DeliveryDelaySampleCount:r.deliveryDelaySampleCount,
        LastOutboundDataAgeMs:outboundAge}
}

// Observed inbound authenticated reverse probes are separately reported.
func (r *reverseTransport) probeAge(now time.Time) int64 {
 r.mu.Lock();defer r.mu.Unlock()
 if r.lastValidProbe.IsZero(){return -1}
 if now.Before(r.lastValidProbe){return 0}
 return int64(now.Sub(r.lastValidProbe).Seconds())
}
func (r *reverseTransport) statistics()(pending int,drops uint64){
    r.mu.Lock();defer r.mu.Unlock()
    return len(r.pending),r.drops
}
