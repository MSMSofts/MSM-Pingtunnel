package pingtunnel

// Reverse ICMP transport primitives. The physical region determines which
// application runs the listener or forwarder; it is NOT the ICMP initiator.
// No unauthenticated probe is permitted to change the selected direction.
import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
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
    // Track recent outbound encrypted Echo Requests to distinguish exact
    // Linux-generated DATA reflections from legitimate Iran->Foreign DATA.
    reverseEchoTrackingWindow = 8 * time.Second
    reverseEchoTrackingCapacity = 16384
)

var reverseProbeMagic = [4]byte{'P','T','R','4'}

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
type reverseSentEchoRecord struct {
    signature reverseSentEchoSignature
    at time.Time
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
    // A bounded ring evicts oldest entries in O(1), without retaining
    // ciphertext. Full-digest comparison happens only for PTD4 Echo Replies.
    outboundEchoes map[reverseSentEchoSignature]time.Time
    outboundEchoRing [reverseEchoTrackingCapacity]reverseSentEchoRecord
    outboundEchoNext int
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
         // Once established, neither an idle application nor a single
         // missing reply can override a continuously verified reverse path.
         if elapsed>=reverseEstablishedGrace && demandDuration>=reverseAbsentGrace &&
           probeAge>=reverseEstablishedGrace && authenticatedAge>=reverseEstablishedGrace {
             allowed=true
             reason="no_authenticated_reverse_traffic_or_polls"
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
    // On a Direct fallback keep testing the reverse path at a bounded rate
    // only when the authenticated Direct channel is stale.
    return r.preference==ICMPAuto && !authenticated
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
    b:=make([]byte,reverseProbeBytes)
    copy(b[:4],reverseProbeMagic[:])
    binary.BigEndian.PutUint64(b[4:12],uint64(now.Unix()))
    if _,err:=rand.Read(b[12:20]);err!=nil{return nil,err}
    tag:=r.mac(b[:20])
    copy(b[20:],tag[:16])
    return b,nil
}

// authenticateProbe is replay-limited and tolerant of modest clock skew.
// Caller must verify the configured remote IP before invoking it.
func (r *reverseTransport) authenticateProbe(frame []byte,now time.Time) bool {
    if len(frame)!=reverseProbeBytes || !hmac.Equal(frame[:4],reverseProbeMagic[:]) {return false}
    seconds:=int64(binary.BigEndian.Uint64(frame[4:12]))
    delta:=now.Unix()-seconds
    if delta<0 {delta=-delta}
    if delta>int64(reverseProbeWindow.Seconds()){return false}
    tag:=r.mac(frame[:20])
    if !hmac.Equal(frame[20:36],tag[:16]){return false}
    var nonce [8]byte
    copy(nonce[:],frame[12:20])
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.recent==nil{r.recent=make(map[[8]byte]time.Time)}
    if _,ok:=r.recent[nonce];ok{return false}
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
        return false
    }
    r.recent[nonce]=now
    r.lastValidProbe=now
    return true
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

// Stage the signature BEFORE the raw socket write, because the peer's Linux
// kernel may echo the request before WriteTo returns. Return the timestamp
// token so a failed write can unregister only the matching registration.
func (r *reverseTransport) stageOutboundDataEcho(id,seq int,payload []byte,now time.Time) (reverseSentEchoSignature,time.Time) {
    key:=reverseEchoSignature(id,seq,payload)
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.outboundEchoes==nil {
        r.outboundEchoes=make(map[reverseSentEchoSignature]time.Time)
    }
    previous:=r.outboundEchoRing[r.outboundEchoNext]
    if !previous.at.IsZero() {
        if at,ok:=r.outboundEchoes[previous.signature];ok && at==previous.at {
            delete(r.outboundEchoes,previous.signature)
        }
    }
    r.outboundEchoRing[r.outboundEchoNext]=reverseSentEchoRecord{signature:key,at:now}
    r.outboundEchoNext=(r.outboundEchoNext+1)%reverseEchoTrackingCapacity
    r.outboundEchoes[key]=now
    return key,now
}

func (r *reverseTransport) cancelOutboundDataEcho(key reverseSentEchoSignature,at time.Time) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if recorded,ok:=r.outboundEchoes[key];ok && recorded==at {
        delete(r.outboundEchoes,key)
    }
}

// Match only a byte-exact echo of our previously transmitted secure DATA.
// A genuine peer frame uses independent AEAD direction keys and will not
// match the sender ciphertext digest. This does not attempt to decrypt,
// replay or alter data; it only eliminates our own reflected packets.
func (r *reverseTransport) filterReflectedDataEcho(id,seq int,payload []byte,now time.Time) bool {
    key:=reverseEchoSignature(id,seq,payload)
    r.mu.Lock()
    defer r.mu.Unlock()
    at,ok:=r.outboundEchoes[key]
    if !ok || now.Before(at) || now.Sub(at)>reverseEchoTrackingWindow {
        return false
    }
    r.reflectedDataEchoes++
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
    period:=250*time.Millisecond
    if !ready {
        period=200*time.Millisecond
    } else {
        // Under BBR/QUIC, a short application pause is not an idle
        // connection: ACKs and loss-recovery packets still need return
        // polling. Keep the previously authenticated burst warm for a
        // bounded jitter window; never run at 2ms solely because a socket
        // remains open.
        if activeConns>0 {period=25*time.Millisecond}
        ageIn:=now.Sub(r.lastUsefulFrame)
        if !r.lastUsefulFrame.IsZero() && ageIn>=0 {
            switch {
            case r.usefulBurst>=4 && ageIn<2400*time.Millisecond:
                period=2*time.Millisecond
            case r.usefulBurst>=2 && ageIn<4500*time.Millisecond:
                if period>6*time.Millisecond {period=6*time.Millisecond}
            case ageIn<4500*time.Millisecond:
                if period>12*time.Millisecond {period=12*time.Millisecond}
            }
        }
        ageOut:=now.Sub(r.lastOutboundData)
        if !r.lastOutboundData.IsZero() && ageOut>=0 {
            switch {
            case r.outboundBurst>=4 && ageOut<4500*time.Millisecond:
                if period>4*time.Millisecond {period=4*time.Millisecond}
            case ageOut<8*time.Second:
                if period>12*time.Millisecond {period=12*time.Millisecond}
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
    OutboundEchoCacheEntries int
    ReplayCapacityRejects uint64
    PollIntervalMillis int
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
    return reverseDiagnostics{Pending:len(r.pending),PendingBytes:r.pendingBytes,
        QueuePeak:r.queuePeak,QueueDrops:r.drops,FailedReplies:r.failedReplies,
        ReflectedPolls:r.reflectedPolls,
        ReflectedDataEchoes:r.reflectedDataEchoes,
        OutboundEchoCacheEntries:len(r.outboundEchoes),
        ReplayCapacityRejects:r.replayCapacityRejects,
        PollIntervalMillis:r.pollPeriodMillis,LastUsefulFrameAgeSeconds:age,
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
