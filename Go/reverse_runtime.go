package pingtunnel

// The reverse leg always uses standards-compliant ICMP echo requests from
// Foreign, and matching echo replies from Iran. It does not attempt to hide
// its authenticated protocol or impersonate other network applications.
import (
    "errors"
    "net"
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
    return recordICMPWriteResult(n,len(data),err)
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

func startReverseHandshake(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time) {
    if c==nil || c.reverse==nil || c.sec==nil || c.sec.region!="iran" {return}
    if c.reverse.preference==ICMPDirect{return}
    // Do not reset an already authenticated reverse session on every
    // authenticated polling request: that caused endless handshakes.
    if useReverse(c) && c.SecureReady() {
        replyReverse(conn,peer,id,seq,c)
        return
    }
    if !c.reverse.allowReverseCandidate(now,c.SecureReady(),c.sec.lastPeerTraffic()) {
        return
    }
    if !useReverse(c) {
        if c.SecureReady(){c.sec.resetForTransportChange()}
        if !c.reverse.choose(ICMPReverse,now){return}
    }
    frame,err:=c.SecureControl(now)
    if err==nil && len(frame)>0{
        _=emitEcho(conn,peer,0,id,seq,frame)
        return
    }
    replyReverse(conn,peer,id,seq,c)
}

func sendForeignPoll(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time,recentlyAuthenticated bool) {
    if c==nil||c.sec==nil||c.sec.region!="foreign"||c.reverse==nil {return}
    authenticated:=recentlyAuthenticated
    // A long-idle authenticated direct link is not automatically considered
    // offline; real app demand or authenticated link degradation is required.
    if !c.reverse.needsProbe(now,authenticated){return}
    // A poll is only a candidate path. Foreign selects Reverse AFTER
    // receiving an authenticated ClientHello inside the matching Echo Reply.
    probe,err:=c.reverse.makeProbe(now)
    if err!=nil{return}
    _=emitEcho(conn,peer,8,id,seq,probe)
}
