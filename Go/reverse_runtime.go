package pingtunnel

// The reverse leg always uses standards-compliant ICMP echo requests from
// Foreign, and matching echo replies from Iran. It does not attempt to hide
// its authenticated protocol or impersonate other network applications.
import (
    "net"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

func useReverse(c *CryptoConfig) bool {
    return c!=nil && c.reverse!=nil && c.reverse.direction()==ICMPReverse
}

func emitEcho(conn icmp.PacketConn,peer *net.IPAddr,typ,id,seq int,body []byte) bool {
    if peer==nil{return false}
    msg:=&icmp.Message{Type:ipv4.ICMPType(typ),Code:0,
        Body:&icmp.Echo{ID:id,Seq:seq,Data:body}}
    data,err:=msg.Marshal(nil)
    if err!=nil{return false}
    n,err:=conn.WriteTo(data,icmpDstAddr(peer))
    return err==nil && n==len(data)
}

// No response is emitted to unauthenticated control or data. This reply is
// called only after a valid paired probe or authenticated session frame.
func replyReverse(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig) {
    if !useReverse(c) || c.sec==nil || c.sec.region!="iran" {return}
    payload:=c.reverse.take(time.Now())
    // An empty Echo Reply is a poll acknowledgement, not an application frame.
    _=emitEcho(conn,peer,0,id,seq,payload)
}

func startReverseHandshake(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time) {
    if c==nil || c.reverse==nil || c.sec==nil || c.sec.region!="iran" {return}
    if c.reverse.preference==ICMPDirect{return}
    if !c.SecureReady(){
        c.reverse.choose(ICMPReverse,now)
        if !useReverse(c){return}
        frame,err:=c.SecureControl(now)
        if err==nil && len(frame)>0{
            _=emitEcho(conn,peer,0,id,seq,frame)
            return
        }
    }
    replyReverse(conn,peer,id,seq,c)
}

func sendForeignPoll(conn icmp.PacketConn,peer *net.IPAddr,id,seq int,c *CryptoConfig,now time.Time) {
    if c==nil||c.sec==nil||c.sec.region!="foreign"||c.reverse==nil {return}
    authenticated:=c.SecureReady()
    // A long-idle authenticated direct link is not automatically considered
    // offline; real app demand or authenticated link degradation is required.
    if !c.reverse.needsProbe(now,authenticated){return}
    if c.reverse.direction()!=ICMPReverse {c.reverse.choose(ICMPReverse,now)}
    if !useReverse(c){return}
    probe,err:=c.reverse.makeProbe(now)
    if err!=nil{return}
    _=emitEcho(conn,peer,8,id,seq,probe)
}
