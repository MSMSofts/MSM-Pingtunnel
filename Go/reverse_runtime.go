package pingtunnel

// The reverse leg always uses standards-compliant ICMP echo requests from
// Foreign, and matching echo replies from Iran. It does not attempt to hide
// its authenticated protocol or impersonate other network applications.
import (
    "errors"
    "net"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

func useReverse(c *CryptoConfig) bool {
    return c!=nil && c.reverse!=nil && c.reverse.direction()==ICMPReverse
}

// These counters cover ALL ICMP transmit paths (direct, reverse, DATA and
// probes). A successful socket write is not proof of delivery to the peer.
var icmpWriteErrors atomic.Uint64
var icmpMessageTooLong atomic.Uint64
var icmpRequestsSent atomic.Uint64
var icmpRepliesSent atomic.Uint64

// Lightweight userspace-only wire accounting. Linux-generated Echo Replies
// are deliberately not counted; a scoped optional nft rule is documented.
var icmpRateSample struct {
    sync.Mutex
    lastAt time.Time
    lastTotal uint64
    currentPPS uint64
    peakPPS uint64
}
func icmpSentRate(now time.Time) (current,peak uint64) {
    total:=icmpRequestsSent.Load()+icmpRepliesSent.Load()
    icmpRateSample.Lock()
    defer icmpRateSample.Unlock()
    if icmpRateSample.lastAt.IsZero() {
        icmpRateSample.lastAt=now
        icmpRateSample.lastTotal=total
    } else if elapsed:=now.Sub(icmpRateSample.lastAt);elapsed>=time.Second {
        delta:=total-icmpRateSample.lastTotal
        icmpRateSample.currentPPS=uint64(float64(delta)/elapsed.Seconds()+0.5)
        if icmpRateSample.currentPPS>icmpRateSample.peakPPS {
            icmpRateSample.peakPPS=icmpRateSample.currentPPS
        }
        icmpRateSample.lastAt=now
        icmpRateSample.lastTotal=total
    }
    return icmpRateSample.currentPPS,icmpRateSample.peakPPS
}

func recordICMPWriteResult(written, expected int, err error) bool {
    if err == nil && written == expected { return true }
    icmpWriteErrors.Add(1)
    if errors.Is(err, syscall.EMSGSIZE) { icmpMessageTooLong.Add(1) }
    return false
}

func emitEcho(conn icmp.PacketConn,peer *net.IPAddr,typ,id,seq int,body []byte) bool {
    if peer==nil{return false}
    msg:=&icmp.Message{Type:ipv4.ICMPType(typ),Code:0,
        Body:&icmp.Echo{ID:id,Seq:seq,Data:body}}
    data,err:=msg.Marshal(nil)
    if err!=nil{return false}
    n,err:=conn.WriteTo(data,icmpDstAddr(peer))
    ok:=recordICMPWriteResult(n,len(data),err)
    if ok {
        if typ==8 {icmpRequestsSent.Add(1)}
        if typ==0 {icmpRepliesSent.Add(1)}
    }
    return ok
}

// No response is emitted to unauthenticated control or data. This reply is
// called only after a valid paired probe or authenticated session frame.
// Dequeue only for an attempted send. On socket failure restore the frame
// ahead of subsequent frames without refreshing its original 12s expiry.
func sendQueuedReverse(r *reverseTransport,now time.Time,write func([]byte)bool) bool {
    f,ok:=r.takeFrame(now)
    // Ordinary idle polling receives the kernel's usual Echo Reply.
    // Avoid injecting a second empty response for every poll.
    if !ok {return true}
    if write(f.data){
        r.noteDeliveredFrame(f.created,now)
        return true
    }
    r.restoreFront(f,now)
    return false
}
func replyReverse(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig) {
    if !useReverse(c) || c.sec==nil || c.sec.region!="iran" {return}
    _=sendQueuedReverse(c.reverse,time.Now(),func(payload []byte)bool{
        // No new framing: preserve standard ICMP Echo Reply and session AEAD.
        return emitEcho(conn,peer,0,id,seq,payload)
    })
}

func startReverseHandshake(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time,switchRequested bool,frameProbe []byte) {
    if c==nil || c.reverse==nil || c.sec==nil || c.sec.region!="iran" {return}
    if c.reverse.preference==ICMPDirect{return}
    // Recovery to preferred Reverse uses a distinct authenticated PTS4
    // request. Do not discard active AEAD keys or queued frames. A
    // matching PTA4 reply lets Foreign switch only after Iran has agreed.
    if switchRequested && c.SecureReady() {
        if !useReverse(c) {
            if !c.reverse.rotateKeepingSession(ICMPReverse,now,"preferred_reverse_recovered"){return}
        }
        ack:=c.reverse.makeSwitchAck(frameProbe,reverseSwitchAckMagic)
        if len(ack)>0 {_=emitEcho(conn,peer,0,id,seq,ack)}
        return
    }
    if !useReverse(c) {
        // Ordinary PTR4 is never authorized to tear down a healthy Direct
        // session. Emergency negotiation remains fail-closed.
        return
    }
    if c.SecureReady(){
        replyReverse(conn,peer,id,seq,c)
        return
    }
    frame,err:=c.SecureControl(now)
    if err==nil && len(frame)>0{
        _=emitEcho(conn,peer,0,id,seq,frame)
        return
    }
    replyReverse(conn,peer,id,seq,c)
}

func sendForeignPoll(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time,recentlyAuthenticated bool,activeConnections ...int) {
    if c==nil||c.sec==nil||c.sec.region!="foreign"||c.reverse==nil {return}
    authenticated:=recentlyAuthenticated
    // A long-idle authenticated direct link is not automatically considered
    // offline; real app demand or authenticated link degradation is required.
    if !c.reverse.needsProbe(now,authenticated){return}
    // While Direct is active, a poll only asks for an independent signed
    // PRA4 proof; two recent matches permit a PTS4/ PTA4 takeover without
    // dropping the current session. Neither a poll nor a mere Ping switches
    // routes. During initial pairing an authenticated ClientHello may select
    // the negotiated path.
    // Never hold the preferred-route return hostage to Direct failure
    // or application activity. Two fresh PRA4 roundtrips are mandatory.
    switchRequest:=c.reverse.takeSwitchRequest(now)
    var probe []byte
    var err error
    if switchRequest {
        probe,err=c.reverse.makeSwitchProbe(now)
    } else {
        probe,err=c.reverse.makeProbe(now)
    }
    if err!=nil{return}
    if switchRequest {c.reverse.stageReverseSwitch(id,seq,probe,now)}
    if !switchRequest {c.reverse.stageProbe(id,seq,probe,now)}
    if emitEcho(conn,peer,8,id,seq,probe) {
        c.reverse.notePollSent()
    } else {
        c.reverse.cancelProbe(id,seq)
    }
}
