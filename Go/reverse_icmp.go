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
)

var reverseProbeMagic = [4]byte{'P','T','R','4'}

type reverseQueuedFrame struct {
    data []byte
    created time.Time
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
    lastValidProbe time.Time
    lastUsefulFrame time.Time
    usefulBurst int
    lastDownstreamFrame time.Time
    downstreamBurst int
    dequeueMaxWait time.Duration
    dequeueWaitEWMANs int64
    dequeueSamples uint64
    lastReceiveAck time.Time
    failedReplies uint64
    reflectedPolls uint64
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
    // 100 polls/second over 20 seconds plus generous network bursts.
    if len(r.recent)>=4096{return false}
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
        wait:=now.Sub(f.created)
        if wait<0{wait=0}
        if wait>r.dequeueMaxWait{r.dequeueMaxWait=wait}
        if r.dequeueSamples==0 {
            r.dequeueWaitEWMANs=int64(wait)
        }else{
            r.dequeueWaitEWMANs+=(int64(wait)-r.dequeueWaitEWMANs)/8
        }
        r.dequeueSamples++
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
// Downstream DATA is sent from Foreign to Iran immediately as encrypted
// Echo Requests. Its activity predicts when the client will need to return
// QUIC acknowledgements in Echo Replies, even if those ACKs are momentarily
// delayed and foreign has not received any useful reverse DATA.
func (r *reverseTransport) noteDownstreamFrame(now time.Time) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if !r.lastDownstreamFrame.IsZero() && now.Sub(r.lastDownstreamFrame)>=0 &&
        now.Sub(r.lastDownstreamFrame)<350*time.Millisecond {
        if r.downstreamBurst<1024{r.downstreamBurst++}
    } else {
        r.downstreamBurst=1
    }
    r.lastDownstreamFrame=now
}

func (r *reverseTransport) pollPeriod(now time.Time,activeConns int,ready bool) time.Duration {
    r.mu.Lock();defer r.mu.Unlock()
    // A reverse poll creates a return-path opportunity. Receive-only
    // scheduling can stall QUIC: if its ACKs slow down, poll pacing also
    // slows, which delays more ACKs. Take the faster of authenticated
    // upstream demand and local encrypted downstream DATA demand.
    period:=250*time.Millisecond
    if !ready {
        period=200*time.Millisecond
    } else {
        if activeConns>0 {period=60*time.Millisecond}
        upstreamAge:=now.Sub(r.lastUsefulFrame)
        if !r.lastUsefulFrame.IsZero() && upstreamAge>=0 {
            switch {
            case upstreamAge<350*time.Millisecond && r.usefulBurst>=4:
                period=2*time.Millisecond
            case upstreamAge<1500*time.Millisecond && r.usefulBurst>=2:
                period=minPollDuration(period,12*time.Millisecond)
            case upstreamAge<3*time.Second:
                period=minPollDuration(period,30*time.Millisecond)
            case upstreamAge<7*time.Second:
                period=minPollDuration(period,50*time.Millisecond)
            }
        }
        downAge:=now.Sub(r.lastDownstreamFrame)
        if !r.lastDownstreamFrame.IsZero() && downAge>=0 {
            switch {
            case downAge<1500*time.Millisecond && r.downstreamBurst>=4:
                period=minPollDuration(period,4*time.Millisecond)
            case downAge<2*time.Second:
                period=minPollDuration(period,12*time.Millisecond)
            case downAge<5*time.Second:
                period=minPollDuration(period,24*time.Millisecond)
            case downAge<8*time.Second:
                period=minPollDuration(period,45*time.Millisecond)
            }
        }
    }
    r.pollPeriodMillis=int(period/time.Millisecond)
    return period
}
func minPollDuration(a,b time.Duration) time.Duration {
    if a<b{return a}
    return b
}

type reverseDiagnostics struct {
    Pending int
    PendingBytes int
    QueuePeak int
    QueueDrops uint64
    FailedReplies uint64
    ReflectedPolls uint64
    PollIntervalMillis int
    LastUsefulFrameAgeSeconds int64
    LastDownstreamAgeSeconds int64
    DequeueMaxWaitMs int64
    DequeueWaitEWMAMs int64
    DequeueSamples uint64
    FallbackCount uint64
    FallbackReason string
}
func (r *reverseTransport) diagnostics(now time.Time)reverseDiagnostics {
    r.mu.Lock();defer r.mu.Unlock()
    age:=int64(-1)
    if !r.lastUsefulFrame.IsZero() {age=int64(now.Sub(r.lastUsefulFrame).Seconds());if age<0{age=0}}
    downAge:=int64(-1)
    if !r.lastDownstreamFrame.IsZero() {
        downAge=int64(now.Sub(r.lastDownstreamFrame).Seconds())
        if downAge<0{downAge=0}
    }
    return reverseDiagnostics{Pending:len(r.pending),PendingBytes:r.pendingBytes,
        LastDownstreamAgeSeconds:downAge,
        DequeueMaxWaitMs:int64(r.dequeueMaxWait/time.Millisecond),
        DequeueWaitEWMAMs:r.dequeueWaitEWMANs/int64(time.Millisecond),
        DequeueSamples:r.dequeueSamples,
        QueuePeak:r.queuePeak,QueueDrops:r.drops,FailedReplies:r.failedReplies,
        ReflectedPolls:r.reflectedPolls,
        PollIntervalMillis:r.pollPeriodMillis,LastUsefulFrameAgeSeconds:age,
        FallbackCount:r.fallbackCount,FallbackReason:r.lastFallbackReason}
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
