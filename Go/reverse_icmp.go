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
    ICMPAutoDirect ICMPDirection = "auto_direct"
    ICMPDirect ICMPDirection = "direct"
    ICMPReverse ICMPDirection = "reverse"
)

func ParseICMPDirection(s string) (ICMPDirection, error) {
    switch ICMPDirection(s) {
    case ICMPAuto, ICMPAutoDirect, ICMPDirect, ICMPReverse:
        return ICMPDirection(s), nil
    default:
        return "", errors.New("icmp_direction must be auto, auto_direct, direct or reverse")
    }
}

const (
    reverseProbeBytes = 36
    reverseProbeWindow = 20 * time.Second
    // The poller can send 500 signed polls/s, retaining roughly 10,000
    // unique nonces inside the 20-second replay window. 4096 rejected
    // otherwise-valid requests every ~8 seconds during active streaming.
    reverseReplayCacheLimit = 16384
    // Only real, queued Iran DATA can wake the idle foreign poller.
    // At most two signed hints per second, and a bounded short poll burst.
    reverseWakeSendCooldown = 500 * time.Millisecond
    reverseWakeReceiveCooldown = 400 * time.Millisecond
    reverseWakeBurst = 1200 * time.Millisecond
    reverseFastPollPeriod = 8 * time.Millisecond
    // Sparse side-channel health checks are safe while Direct carries live
    // user traffic: only signed replies prove that Iran's userspace is alive
    // AND that its Echo Reply can reach Foreign.
    reverseDirectProbeInterval = 10 * time.Second
    directBackgroundProbeInterval = 60 * time.Second
    reverseProofMinInterval = 9 * time.Second
    reverseProofTTL = 25 * time.Second
    // After a failed takeover retry fresh independent proofs after a
    // bounded cooldown; do not wait hours while healthy Reverse is back.
    reverseSwitchRetryCooldown = 30 * time.Second
    // Auto now has a stable preferred path: Reverse. Never rotate a
    // healthy Reverse route on a clock. Retain a zero-valued legacy status
    // field for monitors reading smart_rotation_interval_seconds.
    smartRotationInterval = 0 * time.Second
    smartDirectProofMaxAge = 95 * time.Second
    smartRotationRetryInterval = 2 * time.Second
    smartRotationRetryWindow = 30 * time.Second
    smartRotationFailedCooldown = 5 * time.Minute
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
var reverseWakeMagic = [4]byte{'P','T','W','4'}
var reverseProofMagic = [4]byte{'P','R','A','4'}
var reverseFallbackProofMagic = [4]byte{'P','R','F','4'}
var reverseSwitchMagic = [4]byte{'P','T','S','4'}
var reverseSwitchAckMagic = [4]byte{'P','T','A','4'}
var directSwitchMagic = [4]byte{'P','T','X','4'}
var directSwitchAckMagic = [4]byte{'P','T','B','4'}
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
    directProofConfirmations int
    directRotationRequestedAt time.Time
    directRotationAttemptAt time.Time
    directRotationSequence uint64
    pendingReverseSwitch bool
    pendingDirectSwitch bool
    lastDirectSwitchAttempt time.Time
    directSwitchAttemptAt time.Time
    fallbackProofConfirmations int
    remoteFallbackDemandAt time.Time
    scheduledRotations uint64
    preferredReverseReturns uint64
    rotationRetryCount uint64
    lastRotationReason string
    directProbeChecks uint64
    directPathProofs uint64
    lastProofSent time.Time
    lastProofAt time.Time
    proofConfirmations int
    lastSwitchAttempt time.Time
    reverseSwitchAttemptAt time.Time
    reverseSwitchRetries int
    reverseProofs uint64
    reverseSwitchAttempts uint64
    pollRequests uint64
    pollsSkippedByData uint64
    lastBacklogWake time.Time
    lastAcceptedWake time.Time
    backlogPollUntil time.Time
    backlogWakeSent uint64
    backlogWakeAccepted uint64
    backlogWakeRateLimited uint64
    // Authenticated PTQ4 reports actual remote queue demand without leaking
    // application data. These are separate from routing handoff proofs.
    queueHintSeen map[[8]byte]time.Time
    queueHintAt time.Time
    queueHintDepth int
    queueHintAgeMs int
    queueHintBytes int
    queueHintReceived uint64
    queueHintRejected uint64
    // If socket writes begin failing, reduce ICMP poll pressure temporarily.
    lastObservedICMPWriteFailures uint64
    pollBackoffUntil time.Time
    // Buffered signal removes the artificial 1s idle wait from the first
    // application packet while preserving the ordinary 1Hz idle cadence.
    pollWakeup chan struct{}
    lastUsefulFrame time.Time
    usefulBurst int
    lastOutboundData time.Time
    outboundBurst int
    lastDeliveredQueueDelayMs int64
    lastDeliveredAt time.Time
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
    r:=&reverseTransport{preference:preference,selected:ICMPReverse,started:now,
        // This counter is process-global. Only NEW failures after creating
        // the transport may trigger a 3-second adaptive poll backoff.
        lastObservedICMPWriteFailures:icmpWriteErrors.Load(),
        pollWakeup:make(chan struct{},1)}
    copy(r.secret[:],key)
    if preference==ICMPDirect || preference==ICMPAutoDirect {r.selected=ICMPDirect}
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
 if r.preference==ICMPDirect || r.preference==ICMPAutoDirect{return false}
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
// choose remains the emergency failover operation. Its old queue/session
// invalidation policy is retained for failed paths, not scheduled rotations.
func (r *reverseTransport) choose(direction ICMPDirection, now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if direction!=ICMPDirect && direction!=ICMPReverse{return false}
    if r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect && direction!=r.preference{return false}
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

// rotateKeepingSession moves ONLY the ICMP initiator role. The existing
// Wire-v4 AEAD keys, replay window, application socket maps and Reverse
// encrypted FIFO remain intact. Acknowledgements are HMAC-bound to the exact
// incoming challenge before either side uses this method.
func (r *reverseTransport) rotateKeepingSession(direction ICMPDirection,now time.Time,reason string) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || (direction!=ICMPReverse&&direction!=ICMPDirect) ||
        r.selected==direction || (!r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell) {
        return false
    }
    r.selected=direction
    r.lastSwitch=now
    r.lastRotationReason=reason
    r.scheduledRotations++
    if (r.preference==ICMPAuto && direction==ICMPReverse) ||
       (r.preference==ICMPAutoDirect && direction==ICMPDirect) {r.preferredReverseReturns++}
    r.proofConfirmations=0
    r.directProofConfirmations=0
    r.lastProofAt=time.Time{}
    r.probeChallenges=nil
    r.directProbeChallenges=nil
    r.directRotationRequestedAt=time.Time{}
    r.directRotationAttemptAt=time.Time{}
    r.pendingReverseSwitch=false
    r.pendingDirectSwitch=false
    r.fallbackProofConfirmations=0
    r.remoteFallbackDemandAt=time.Time{}
    return true
}
// Legacy API is deliberately inert: rotating Reverse->Direct on a timer
// conflicts with the preferred-Reverse policy and causes unnecessary jitter.
// Direct is selected only by fallbackDirect after a sustained Reverse outage.
func (r *reverseTransport) rotationDueLocked(now time.Time) bool {
    return false
}
func (r *reverseTransport) rotationDue(now time.Time) bool {
    return false
}
func (r *reverseTransport) shouldRequestDirectRotation(now time.Time,ready bool) bool {
    return false
}
// A pending request keeps the same socket/session as Reverse and retries the
// HMACed handoff until its paired foreign userspace ACK arrives.
func (r *reverseTransport) stageDirectSwitch(id,seq int,payload []byte,now time.Time) {
    r.stageDirectProbe(id,seq,payload,now)
}
func (r *reverseTransport) acceptDirectSwitchProof(id,seq int,reply []byte,now time.Time) bool {
    if len(reply)!=reverseProbeBytes||!bytes.Equal(reply[:4],directSwitchAckMagic[:]){return false}
    tag:=r.mac(reply[:20])
    if !hmac.Equal(tag[:16],reply[20:36]){return false}
    r.mu.Lock();defer r.mu.Unlock()
    if r.preference!=ICMPAutoDirect || r.selected!=ICMPReverse ||
        !r.pendingDirectSwitch {return false}
    key:=probeChallengeKey(id,seq)
    challenge,ok:=r.directProbeChallenges[key]
    if !ok || now.Before(challenge.sentAt) || now.Sub(challenge.sentAt)>reverseProofTTL ||
        !bytes.Equal(challenge.first20[:4],directSwitchMagic[:]) ||
        !hmac.Equal(reply[4:20],challenge.first20[4:20]) {
        return false
    }
    delete(r.directProbeChallenges,key)
    r.pendingDirectSwitch=false
    return true
}
func (r *reverseTransport) makeSwitchAck(probe []byte,magic [4]byte) []byte {
    if len(probe)!=reverseProbeBytes{return nil}
    reply:=append([]byte(nil),probe...)
    copy(reply[:4],magic[:])
    tag:=r.mac(reply[:20])
    copy(reply[20:],tag[:16])
    return reply
}
func (r *reverseTransport) stageReverseSwitch(id,seq int,probe []byte,now time.Time) {
    r.stageProbe(id,seq,probe,now)
}
func (r *reverseTransport) acceptReverseSwitchProof(id,seq int,reply []byte,now time.Time) bool {
    if len(reply)!=reverseProbeBytes||!bytes.Equal(reply[:4],reverseSwitchAckMagic[:]){return false}
    tag:=r.mac(reply[:20])
    if !hmac.Equal(tag[:16],reply[20:36]){return false}
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPDirect{return false}
    key:=probeChallengeKey(id,seq)
    challenge,ok:=r.probeChallenges[key]
    if !ok || now.Before(challenge.sentAt)||now.Sub(challenge.sentAt)>reverseProofTTL ||
        !bytes.Equal(challenge.first20[:4],reverseSwitchMagic[:])||
        !hmac.Equal(reply[4:20],challenge.first20[4:20]){return false}
    delete(r.probeChallenges,key)
    return true
}
// Emergency Reverse outage handling is independent of Smart Rotation.
 // Direct is permitted on sustained authenticated Reverse failure,
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

// Prevent the generic 35s Iran AEAD watchdog from tearing down a
// Direct-first session *before* two signed PRF4 proofs can authorize a
// Direct->Reverse fallback. After five minutes of sustained demand with
// no recovery, permit ordinary rekey. An explicit HMACed PTS4 can still
// take over Reverse while that new handshake is incomplete.
func (r *reverseTransport) deferDirectRecoveryRekey(now time.Time) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    return r.preference==ICMPAutoDirect && r.selected==ICMPDirect &&
        !r.demandSince.IsZero() && !now.Before(r.demandSince) &&
        now.Sub(r.demandSince)<5*time.Minute
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
    if r.preference==ICMPAutoDirect{return true}
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
// Wake-up frames are NOT transport-switch intents, handshake controls,
// application DATA or acknowledgement of a healthy two-way link.
// They only remove the next scheduled poller's idle sleep on genuine demand.
func (r *reverseTransport) makeBacklogWake(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,reverseWakeMagic)
}
func (r *reverseTransport) authenticateBacklogWake(frame []byte,now time.Time) bool {
    if len(frame)!=reverseProbeBytes || !bytes.Equal(frame[:4],reverseWakeMagic[:]) {
        return false
    }
    ok,sw:=r.authenticateProbeWithSwitch(frame,now)
    return ok && !sw
}
// On the Iran VPS, the data must already be encrypted and queued before
// deciding to emit a single, short, key-authenticated hint.
func (r *reverseTransport) allowBacklogWake(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if r.selected!=ICMPReverse || len(r.pending)==0 {
        return false
    }
    if !r.lastBacklogWake.IsZero() &&
        now.Sub(r.lastBacklogWake)<reverseWakeSendCooldown{return false}
    r.lastBacklogWake=now
    return true
}
func (r *reverseTransport) noteBacklogWakeSent(){
    r.mu.Lock();r.backlogWakeSent++;r.mu.Unlock()
}
// The foreign server accepts only verified requests from its pinned peer.
// An in-memory, non-blocking notification wakes the single timer-based
// poller; no second poller or parallel burst loop is ever started.
func (r *reverseTransport) noteAuthenticatedBacklogWake(now time.Time) bool {
    r.mu.Lock()
    if r.selected!=ICMPReverse || (!r.lastAcceptedWake.IsZero() &&
        now.Sub(r.lastAcceptedWake)<reverseWakeReceiveCooldown) {
        r.backlogWakeRateLimited++
        r.mu.Unlock()
        return false
    }
    r.lastAcceptedWake=now
    r.backlogPollUntil=now.Add(reverseWakeBurst)
    r.backlogWakeAccepted++
    r.mu.Unlock()
    select{case r.pollWakeup<-struct{}{}:default:}
    return true
}
func (r *reverseTransport) makeSwitchProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,reverseSwitchMagic)
}
func (r *reverseTransport) makeDirectProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,directProbeMagic)
}
func (r *reverseTransport) makeDirectSwitchProbe(now time.Time) ([]byte,error) {
    return r.makeProbeType(now,directSwitchMagic)
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
func (r *reverseTransport) authenticateDirectSwitchProbe(frame []byte,now time.Time) bool {
    if len(frame)!=reverseProbeBytes||!bytes.Equal(frame[:4],directSwitchMagic[:]){return false}
    valid,_:=r.authenticateProbeWithSwitch(frame,now)
    return valid
}
func (r *reverseTransport) authenticateProbeWithSwitch(frame []byte,now time.Time) (valid,switchRequest bool) {
    if len(frame)!=reverseProbeBytes{return false,false}
    isProbe:=bytes.Equal(frame[:4],reverseProbeMagic[:])
    isSwitch:=bytes.Equal(frame[:4],reverseSwitchMagic[:])
    isDirect:=bytes.Equal(frame[:4],directProbeMagic[:])
    isDirectSwitch:=bytes.Equal(frame[:4],directSwitchMagic[:])
    isWake:=bytes.Equal(frame[:4],reverseWakeMagic[:])
    if !isProbe && !isSwitch && !isDirect && !isDirectSwitch && !isWake{return false,false}
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
    if !isDirect && !isDirectSwitch && !isWake{r.lastValidProbe=now}
    return true,isSwitch
}

// A PRF4 proof is a signed declaration by Iran that authenticated Direct
// replies are NOT arriving despite genuine local application demand. This
// cannot be inferred from the last data RECEIVED by Foreign: on a one-way
// failure Iran->Foreign still works but Foreign->Iran does not. An idle or
// healthy Direct route always returns the ordinary PRA4 proof instead.
//
// at[0] is the testable local clock. at[1] is Iran's last authenticated
// Foreign->Iran arrival, not a Foreign-side observation. Require BOTH
// measurements to authorize an emergency direction change. With no prior
// established session, allow startup recovery only after a 90s initial
// wait and sustained demand; never treat an immediate empty timestamp as
// evidence of a broken session.
func (r *reverseTransport) makeProof(probe []byte,at ...time.Time) []byte {
    now:=time.Now()
    if len(at)>0 {now=at[0]}
    r.mu.Lock()
    activeDemand:=r.preference==ICMPAutoDirect && r.selected==ICMPDirect &&
        !r.lastDemand.IsZero() && !now.Before(r.lastDemand) &&
        now.Sub(r.lastDemand)<5*time.Second &&
        !r.demandSince.IsZero() && !now.Before(r.demandSince)
    priorStart:=r.started
    demandAt:=r.demandSince
    r.mu.Unlock()
    staleDirect:=false
    if len(at)>1 && activeDemand {
        lastPeer:=at[1]
        if lastPeer.IsZero() {
            // No authenticated Direct handshake ever completed.
            staleDirect=!now.Before(priorStart) &&
                now.Sub(priorStart)>=reverseEstablishedGrace &&
                now.Sub(demandAt)>=reverseAbsentGrace
        } else {
            // Direct completed before; recover from one-way stalls after
            // 35 seconds with real application demand. An idle tunnel is
            // not interpreted as failure by this check.
            staleDirect=!now.Before(lastPeer) &&
                now.Sub(lastPeer)>=35*time.Second &&
                now.Sub(demandAt)>=reverseAbsentGrace
        }
    }
    if staleDirect {return r.makeSwitchAck(probe,reverseFallbackProofMagic)}
    return r.makeSwitchAck(probe,reverseProofMagic)
}
func (r *reverseTransport) makeDirectProof(probe []byte) []byte {
    return r.makeSwitchAck(probe,directProofMagic)
}
// Low-rate, authenticated Direct reachability check; it never selects
// Direct or resets the preferred Reverse session while healthy.
func (r *reverseTransport) shouldProbeDirect(now time.Time,ready bool) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPReverse || !ready{return false}
    cadence:=directBackgroundProbeInterval
    if r.preference==ICMPAutoDirect {cadence=reverseDirectProbeInterval}
    if !r.lastDirectProbe.IsZero() && now.Sub(r.lastDirectProbe)<cadence{return false}
    r.lastDirectProbe=now
    r.directProbeChecks++
    return true
}
func (r *reverseTransport) stageDirectProbe(id,seq int,probe []byte,now time.Time) {
    if len(probe)!=reverseProbeBytes{return}
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPReverse{return}
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
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPReverse{return false}
    key:=probeChallengeKey(id,seq)
    challenge,ok:=r.directProbeChallenges[key]
    if !ok || now.Before(challenge.sentAt)||now.Sub(challenge.sentAt)>reverseProofTTL{return false}
    if !hmac.Equal(reply[4:20],challenge.first20[4:20]){return false}
    delete(r.directProbeChallenges,key)
    r.directPathProofs++
    if r.lastDirectProof.IsZero() || now.Sub(r.lastDirectProof)>2*directBackgroundProbeInterval+10*time.Second {
        r.directProofConfirmations=0
    }
    if r.directProofConfirmations<2 {r.directProofConfirmations++}
    r.lastDirectProof=now
    return true
}
func (r *reverseTransport) allowDirectPathProof(now time.Time) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPDirect{return false}
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
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPDirect{return}
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
    if len(reply)!=reverseProbeBytes ||
        (!bytes.Equal(reply[:4],reverseProofMagic[:]) &&
         !bytes.Equal(reply[:4],reverseFallbackProofMagic[:])){return false}
    mac:=r.mac(reply[:20])
    if !hmac.Equal(reply[20:],mac[:16]){return false}
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPDirect{return false}
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
    if bytes.Equal(reply[:4],reverseFallbackProofMagic[:]) {
        if r.fallbackProofConfirmations<reverseRequiredProofs {r.fallbackProofConfirmations++}
        r.remoteFallbackDemandAt=now
    } else if r.preference==ICMPAutoDirect {
        r.fallbackProofConfirmations=0
        r.remoteFallbackDemandAt=time.Time{}
    }
    if r.proofConfirmations<reverseRequiredProofs{r.proofConfirmations++}
    r.lastProofAt=now
    r.reverseProofs++
    return true
}
// Call on the foreign poller only, after two separate successful proofs.
// Never reset the healthy Direct AEAD session merely due to a timer.
// Foreign returns Direct->Reverse as soon as it has two independent,
// fresh authenticated return-path proofs and the minimum dwell is met,
// even when Direct is working. No timed healthy-path rotation or user
// demand is needed. Retry every 2s for up to 30s in case
// the matching PTA4 ACK was lost. No half-verified path can force a switch.
func (r *reverseTransport) takeSwitchRequest(now time.Time,emergency ...bool) bool {
    r.mu.Lock();defer r.mu.Unlock()
    if (r.preference!=ICMPAuto && r.preference!=ICMPAutoDirect) || r.selected!=ICMPDirect{return false}
    if r.preference==ICMPAutoDirect {
        verifiedDemand:=r.fallbackProofConfirmations>=reverseRequiredProofs &&
            !r.remoteFallbackDemandAt.IsZero() &&
            now.Sub(r.remoteFallbackDemandAt)>=0 &&
            now.Sub(r.remoteFallbackDemandAt)<=reverseProofTTL
        degraded:=len(emergency)>0 && emergency[0]
        if !verifiedDemand || !degraded {
            r.pendingReverseSwitch=false
            return false
        }
    }
    if !r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell{return false}
    if r.pendingReverseSwitch {
        if now.Sub(r.lastSwitchAttempt)>smartRotationRetryWindow {
            r.pendingReverseSwitch=false
            r.proofConfirmations=0
            r.lastSwitchAttempt=now
            r.rotationRetryCount++
            return false
        }
        if now.Sub(r.reverseSwitchAttemptAt)<smartRotationRetryInterval{return false}
        r.reverseSwitchAttemptAt=now
        r.reverseSwitchRetries++
        return true
    }
    // The optional legacy emergency argument is ignored: only matched,
    // fresh, independent PRA4 proofs authorize a preferred-route takeover.
    if r.proofConfirmations<reverseRequiredProofs ||
        r.lastProofAt.IsZero() || now.Sub(r.lastProofAt)>reverseProofTTL ||
        (!r.lastSwitchAttempt.IsZero() && now.Sub(r.lastSwitchAttempt)<reverseSwitchRetryCooldown) {
        return false
    }
    r.lastSwitchAttempt=now
    r.reverseSwitchAttemptAt=now
    r.reverseSwitchAttempts++
    r.proofConfirmations=0
    r.pendingReverseSwitch=true
    return true
}
// Direct-first recovery is symmetric with the Reverse-first verified return:
// two independent HMAC-proven PTC4/PDA4 roundtrips trigger a signed PTX4.
// Only the Iranian peer requests this switch, and it must see a matching
// PTB4 acknowledgment before leaving Reverse. The foreign side handles
// lost-ACK retransmissions idempotently.
func (r *reverseTransport) takeDirectSwitchRequest(now time.Time) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.preference!=ICMPAutoDirect || r.selected!=ICMPReverse {return false}
    if !r.lastSwitch.IsZero() && now.Sub(r.lastSwitch)<reverseMinDwell{return false}
    if r.pendingDirectSwitch {
        if now.Sub(r.lastDirectSwitchAttempt)>smartRotationRetryWindow {
            r.pendingDirectSwitch=false
            r.directProofConfirmations=0
            r.lastDirectSwitchAttempt=now
            r.rotationRetryCount++
            return false
        }
        if now.Sub(r.directSwitchAttemptAt)<smartRotationRetryInterval{return false}
        r.directSwitchAttemptAt=now
        return true
    }
    if r.directProofConfirmations<reverseRequiredProofs ||
        r.lastDirectProof.IsZero() ||
        now.Sub(r.lastDirectProof)>reverseProofTTL ||
        (!r.lastDirectSwitchAttempt.IsZero() &&
          now.Sub(r.lastDirectSwitchAttempt)<reverseSwitchRetryCooldown) {
        return false
    }
    r.pendingDirectSwitch=true
    r.lastDirectSwitchAttempt=now
    r.directSwitchAttemptAt=now
    r.reverseSwitchAttempts++
    return true
}

// True only for the selected Direct-first AUTO policy. A paired PTX4
// cannot switch either fixed/manual direction or Reverse-preferred AUTO.
func (r *reverseTransport) allowSignedDirectTakeover() (selected ICMPDirection,ok bool) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.preference!=ICMPAutoDirect{return "",false}
    return r.selected,true
}

// During an authenticated PTA4 handoff use bounded 2s retransmission
// intervals, otherwise a Direct-mode 10s health probe is sufficient.
func (r *reverseTransport) directMonitorPeriod() time.Duration {
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.selected==ICMPDirect && r.pendingReverseSwitch {
        return smartRotationRetryInterval
    }
    return reverseDirectProbeInterval
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
    // A successfully authenticated, reassembled DATA message is an
    // independent sign of completed Reverse delivery. Reduce the remote
    // backlog estimate instead of polling for packets already received.
    // Partial fragments do not reach this function.
    if r.queueHintDepth>0 && !r.queueHintAt.IsZero() &&
        !now.Before(r.queueHintAt) && now.Sub(r.queueHintAt)<6*time.Second {
        r.queueHintDepth--
        if r.queueHintDepth==0 {
            r.queueHintBytes=0
            r.queueHintAgeMs=0
        }
    }
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
        if activeConns>0 {period=25*time.Millisecond}
        ageIn:=now.Sub(r.lastUsefulFrame)
        if !r.lastUsefulFrame.IsZero() && ageIn>=0 {
            switch {
            case r.usefulBurst>=4 && ageIn<2400*time.Millisecond:
                period=reverseFastPollPeriod
            case r.usefulBurst>=2 && ageIn<4500*time.Millisecond:
                if period>12*time.Millisecond {period=12*time.Millisecond}
            case ageIn<4500*time.Millisecond:
                if period>20*time.Millisecond {period=20*time.Millisecond}
            }
        }
        ageOut:=now.Sub(r.lastOutboundData)
        if !r.lastOutboundData.IsZero() && ageOut>=0 {
            switch {
            case r.outboundBurst>=4 && ageOut<4500*time.Millisecond:
                if period>10*time.Millisecond {period=10*time.Millisecond}
            case ageOut<8*time.Second:
                if period>20*time.Millisecond {period=20*time.Millisecond}
            }
        }
        // Keep authenticated, not-yet-drained remote pressure warm for
        // at most 6s rather than prematurely sleeping at a 1s cadence.
        // The 25ms floor disappears when all reported DATA arrives.
        if r.queueHintDepth>0 && !r.queueHintAt.IsZero() &&
            !now.Before(r.queueHintAt) && now.Sub(r.queueHintAt)<6*time.Second &&
            period>25*time.Millisecond { period=25*time.Millisecond }
        // Smart queue-aware scheduling: Iranian PTQ4 signals are signed
        // observations of actual encrypted FIFO depth and oldest age, not
        // guesses based on a TCP congestion window or a video buffer.
        // Fresh pressure speeds polling; a drained/stale queue decays back
        // to the ordinary demand-driven rate. Single-packet game bursts
        // avoid an unconditional 125 Hz poll storm.
        if !r.backlogPollUntil.IsZero() &&
            !now.Before(r.lastAcceptedWake) && now.Before(r.backlogPollUntil) {
            hintFresh:=!r.queueHintAt.IsZero() && !now.Before(r.queueHintAt) &&
                now.Sub(r.queueHintAt)<reverseWakeBurst
            if hintFresh {
                if r.queueHintDepth>0 {
                    hintTarget:=reverseQueueHintPollInterval(r.queueHintDepth,r.queueHintAgeMs)
                    // Rapid attack, slower decay: on a brand-new genuine
                    // game packet give the queue an immediate small 8ms
                    // retry window; once the initial 120ms passes, use
                    // measured backlog rather than keeping 125 polls/s.
                    if now.Sub(r.queueHintAt)<120*time.Millisecond {
                        hintTarget=reverseFastPollPeriod
                    }
                    if period>hintTarget {period=hintTarget}
                }
            } else if period>reverseFastPollPeriod {
                // Older PTW4 peers cannot report queue measurements. Keep
                // their existing 8ms bounded wake behavior compatible.
                period=reverseFastPollPeriod
            }
        }
    }
    // ICMP socket errors are an immediate local congestion signal: do
    // not drive 125 polls/s into an already failing raw socket. Use a
    // bounded 3-second respite with 25ms minimum; resume automatically.
    errorsNow:=icmpWriteErrors.Load()
    if errorsNow>r.lastObservedICMPWriteFailures {
        r.pollBackoffUntil=now.Add(3*time.Second)
        r.lastObservedICMPWriteFailures=errorsNow
    }
    if now.Before(r.pollBackoffUntil) && period<25*time.Millisecond {
        period=25*time.Millisecond
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
    r.lastDeliveredAt=now
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
    ScheduledRotations uint64
    PreferredReverseReturns uint64
    ReverseProofConfirmations int
    PendingPreferredReverse bool
    LastReverseProofAgeMs int64
    RotationRetryCount uint64
    RotationDue bool
    LastRotationReason string
    DirectProofConfirmations int
    PollRequests uint64
    PollsSkippedByData uint64
    BacklogWakeSent uint64
    BacklogWakeAccepted uint64
    BacklogWakeRateLimited uint64
    BacklogWakeActiveMs int64
    QueueHintDepth int
    QueueHintAgeMs int
    QueueHintBytes int
    QueueHintAgeSinceReceivedMs int64
    QueueHintsReceived uint64
    QueueHintsRejected uint64
    PollBackoffRemainingMs int64
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
    LastDeliveryAgeSeconds int64
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
    reverseProofAge:=int64(-1)
    if !r.lastProofAt.IsZero() {
        d:=now.Sub(r.lastProofAt)
        if d<0{d=0}
        reverseProofAge=int64(d/time.Millisecond)
    }
    directProofAge:=int64(-1)
    if !r.lastDirectProof.IsZero(){
        directProofAge=int64(now.Sub(r.lastDirectProof).Seconds())
        if directProofAge<0{directProofAge=0}
    }
    deliveryAge:=int64(-1)
    if !r.lastDeliveredAt.IsZero() {
        d:=now.Sub(r.lastDeliveredAt)
        if d<0 {d=0}
        deliveryAge=int64(d/time.Second)
    }
    hintAgeSince:=int64(-1)
    if !r.queueHintAt.IsZero() {
        gap:=now.Sub(r.queueHintAt)
        if gap<0 {gap=0}
        hintAgeSince=int64(gap/time.Millisecond)
    }
    backoffRemaining:=int64(0)
    if now.Before(r.pollBackoffUntil) {
        backoffRemaining=int64(r.pollBackoffUntil.Sub(now)/time.Millisecond)
    }
    wakeRemaining:=int64(0)
    if now.Before(r.backlogPollUntil) {
        wakeRemaining=int64(r.backlogPollUntil.Sub(now)/time.Millisecond)
    }
    switchAge:=int64(-1)
    if !r.lastSwitch.IsZero(){
        switchAge=int64(now.Sub(r.lastSwitch).Seconds())
        if switchAge<0{switchAge=0}
    }
    reportedDepth,reportedOldest,reportedBytes:=r.queueHintDepth,r.queueHintAgeMs,r.queueHintBytes
    if r.queueHintAt.IsZero() || now.Sub(r.queueHintAt)>reverseWakeBurst {
        reportedDepth,reportedOldest,reportedBytes=0,0,0
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
        ScheduledRotations:r.scheduledRotations,PreferredReverseReturns:r.preferredReverseReturns,
        ReverseProofConfirmations:r.proofConfirmations,PendingPreferredReverse:r.pendingReverseSwitch,
        LastReverseProofAgeMs:reverseProofAge,
        RotationRetryCount:r.rotationRetryCount,
        RotationDue:r.rotationDueLocked(now),LastRotationReason:r.lastRotationReason,
        DirectProofConfirmations:r.directProofConfirmations,
        PollRequests:r.pollRequests,PollsSkippedByData:r.pollsSkippedByData,
        BacklogWakeSent:r.backlogWakeSent,BacklogWakeAccepted:r.backlogWakeAccepted,
        BacklogWakeRateLimited:r.backlogWakeRateLimited,
        BacklogWakeActiveMs:wakeRemaining,
        QueueHintDepth:reportedDepth,QueueHintAgeMs:reportedOldest,
        QueueHintBytes:reportedBytes,QueueHintAgeSinceReceivedMs:hintAgeSince,
        QueueHintsReceived:r.queueHintReceived,QueueHintsRejected:r.queueHintRejected,
        PollBackoffRemainingMs:backoffRemaining,
        DirectProbeChecks:r.directProbeChecks,DirectPathProofs:r.directPathProofs,
        DirectLastProofAgeSeconds:directProofAge,
        LastSwitchAgeSeconds:switchAge,
        FallbackCount:r.fallbackCount,FallbackReason:r.lastFallbackReason,
        OldestQueueAgeMs:oldest,LastQueueDelayMs:r.lastDeliveredQueueDelayMs,
        MaxQueueDelayMs:r.maxDeliveredQueueDelayMs,DeliveredFrames:r.deliveredFrames,
        DelayedFrames:r.delayedFrames,VeryDelayedFrames:r.veryDelayedFrames,
        MeanQueueDelayMs:avgDelay,P95QueueDelayMs:p95Delay,
        DeliveryDelaySampleCount:r.deliveryDelaySampleCount,
        LastDeliveryAgeSeconds:deliveryAge,LastOutboundDataAgeMs:outboundAge}
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
