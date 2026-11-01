package pingtunnel

import (
    "bytes"
    "encoding/binary"
    "sync"
    "testing"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

// PING, DATA, and a possible authenticated KICK are all secure PTD4 frames.
// They may all be reflected by the Iran kernel, but only real DATA may
// accelerate adaptive BBR/QUIC return polling.
func TestReversePTD4PingClassificationAndExactReply(t *testing.T) {
    start:=time.Unix(1900000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0x81},32),start)
    foreign:=&CryptoConfig{sec:&secureSession{region:"foreign"},reverse:r}
    iran:=&CryptoConfig{sec:&secureSession{region:"iran"},reverse:r}
    if reverseEchoKindForMessage(uint32(MyMsg_DATA))!=reverseEchoDATA ||
        reverseEchoKindForMessage(uint32(MyMsg_PING))!=reverseEchoPING ||
        reverseEchoKindForMessage(uint32(MyMsg_KICK))!=reverseEchoOther {
        t.Fatal("encrypted message type classification is wrong")
    }
    if d:=r.diagnostics(start);d.LastOutboundDataAgeMs!=-1 {
        t.Fatalf("idle link incorrectly recorded app DATA: %+v",d)
    }
    ping:=append([]byte("PTD4"),bytes.Repeat([]byte{0x38},96)...)
    key,at:=r.stageOutboundEcho(0x42a5,330,ping,reverseEchoKindForMessage(uint32(MyMsg_PING)),start)
    // Make an actual Linux-style Echo Request and copied Echo Reply.
    outgoing,err:=(&icmp.Message{Type:ipv4.ICMPTypeEcho,Code:0,
        Body:&icmp.Echo{ID:0x42a5,Seq:330,Data:ping}}).Marshal(nil)
    if err!=nil{t.Fatal(err)}
    reply,err:=(&icmp.Message{Type:ipv4.ICMPTypeEchoReply,Code:0,
        Body:&icmp.Echo{ID:0x42a5,Seq:330,Data:ping}}).Marshal(nil)
    if err!=nil{t.Fatal(err)}
    id:=int(binary.BigEndian.Uint16(reply[4:6]))
    seq:=int(binary.BigEndian.Uint16(reply[6:8]))
    if isReflectedReverseDataEcho(foreign,outgoing[0],id,seq,outgoing[8:],start.Add(time.Millisecond)){
        t.Fatal("outgoing Echo Request was treated as a reflected response")
    }
    if isReflectedReverseDataEcho(iran,reply[0],id,seq,reply[8:],start.Add(time.Millisecond)){
        t.Fatal("Iran endpoint may not apply foreign echo filter")
    }
    before:=foreign.sec.stats().AuthenticationFailures
    if !isReflectedReverseDataEcho(foreign,reply[0],id,seq,reply[8:],start.Add(time.Millisecond)){
        t.Fatal("exact reflected PTD4 PING was not recognized before AEAD")
    }
    d:=r.diagnostics(start.Add(time.Millisecond))
    if d.ReflectedPingEchoes!=1 || d.ReflectedDataEchoes!=0 || d.ReflectedOtherEchoes!=0 ||
        d.OutboundEchoCacheEntries!=1 || d.LastOutboundDataAgeMs!=-1 {
        t.Fatalf("PING reflection contaminated DATA counters or poll state: %+v",d)
    }
    if got:=r.pollPeriod(start.Add(2*time.Millisecond),1,true);got!=25*time.Millisecond{
        t.Fatalf("PING alone accelerated application return polls: %s",got)
    }
    if foreign.sec.stats().AuthenticationFailures!=before {
        t.Fatal("filtered PING reflection inflated AEAD auth failures")
    }
    different:=bytes.Clone(ping)
    different[len(different)-1]^=0x01
    if isReflectedReverseDataEcho(foreign,0,id,seq,different,start.Add(3*time.Millisecond)){
        t.Fatal("legitimate DIFFERENT peer PTD4 (same ICMP echo numbers) was suppressed")
    }
    r.cancelOutboundDataEcho(key,at)
    if isReflectedReverseDataEcho(foreign,0,id,seq,ping,start.Add(4*time.Millisecond)){
        t.Fatal("failed PING socket write remained eligible for suppression")
    }
}

func TestReversePTD4PingOtherAndDataCountersStayIndependent(t *testing.T){
    start:=time.Unix(1900000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0x82},32),start)
    for i,kind:=range []reverseEchoKind{reverseEchoPING,reverseEchoDATA,reverseEchoOther}{
        p:=append([]byte("PTD4"),bytes.Repeat([]byte{byte(i+1)},90)...)
        r.stageOutboundEcho(0x42a5,i+1,p,kind,start.Add(time.Duration(i)*time.Millisecond))
        if !r.filterReflectedDataEcho(0x42a5,i+1,p,start.Add(10*time.Millisecond)){
            t.Fatalf("missing exact reflection for kind %d",kind)
        }
    }
    d:=r.diagnostics(start.Add(15*time.Millisecond))
    if d.ReflectedPingEchoes!=1||d.ReflectedDataEchoes!=1||d.ReflectedOtherEchoes!=1{
        t.Fatalf("message-kind counters not isolated: %+v",d)
    }
}

func TestReverseEchoCachePrunesExpiredEntriesDuringStatusAndStreaming(t *testing.T){
    start:=time.Unix(1900000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0x83},32),start)
    const count=900
    // More than 8 seconds of data and health PINGs; no idle stale map growth.
    for i:=0;i<count;i++{
        now:=start.Add(time.Duration(i)*100*time.Millisecond)
        p:=append([]byte("PTD4"),bytes.Repeat([]byte{0x78},72)...)
        binary.BigEndian.PutUint32(p[8:12],uint32(i))
        kind:=reverseEchoDATA
        if i%3==0 {kind=reverseEchoPING}
        r.stageOutboundEcho(0x42a5,i,p,kind,now)
        if i%20==0 {
            d:=r.diagnostics(now)
            if d.OutboundEchoCacheEntries>82 {
                t.Fatalf("expired fingerprints were not reclaimed during sustained streaming: %+v",d)
            }
            if d.CapacityEvictedEchoSignatures!=0{
                t.Fatalf("light stream should not fill bounded cache: %+v",d)
            }
        }
    }
    end:=start.Add(90*time.Second+reverseEchoTrackingWindow)
    d:=r.diagnostics(end)
    if d.OutboundEchoCacheEntries!=0 || d.ExpiredEchoSignatures!=count ||
        d.CapacityEvictedEchoSignatures!=0 {
        t.Fatalf("status did not purge stale PING/DATA signatures: %+v",d)
    }
    d=r.diagnostics(end.Add(time.Second))
    if d.ExpiredEchoSignatures!=count{
        t.Fatal("expired fingerprints were counted more than once")
    }
}

func TestReverseEchoCacheCapacityEvictsOnlyOldestEligibleSignatures(t *testing.T){
    start:=time.Unix(1900000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0x84},32),start)
    // A burst within the eight-second window fills the fixed ring.
    for i:=0;i<reverseEchoTrackingCapacity+3;i++{
        p:=append([]byte("PTD4"),bytes.Repeat([]byte{0x77},48)...)
        binary.BigEndian.PutUint32(p[8:12],uint32(i))
        r.stageOutboundEcho(0x42a5,i,p,reverseEchoDATA,start.Add(time.Duration(i)*time.Microsecond))
    }
    d:=r.diagnostics(start.Add(time.Second))
    if d.OutboundEchoCacheEntries!=reverseEchoTrackingCapacity ||
        d.CapacityEvictedEchoSignatures!=3 || d.ExpiredEchoSignatures!=0 {
        t.Fatalf("bounded cache eviction accounting wrong: %+v",d)
    }
    p:=append([]byte("PTD4"),bytes.Repeat([]byte{0x77},48)...)
    binary.BigEndian.PutUint32(p[8:12],0)
    if r.filterReflectedDataEcho(0x42a5,0,p,start.Add(time.Second)){
        t.Fatal("capacity-evicted old signature matched")
    }
}

func TestReverseEchoCacheConcurrentPruneReadAndWrite(t *testing.T) {
    start:=time.Unix(1900000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{0x85},32),start)
    var wg sync.WaitGroup
    for g:=0;g<8;g++{
        wg.Add(1)
        go func(g int) {
            defer wg.Done()
            for i:=0;i<200;i++{
                now:=start.Add(time.Duration(i)*time.Millisecond)
                p:=append([]byte("PTD4"),bytes.Repeat([]byte{0x90},60)...)
                binary.BigEndian.PutUint32(p[8:12],uint32(g*200+i))
                key,at:=r.stageOutboundEcho(0x42a5,g*200+i,p,reverseEchoPING,now)
                _=r.filterReflectedDataEcho(0x42a5,g*200+i,p,now.Add(time.Millisecond))
                r.cancelOutboundDataEcho(key,at)
                _=r.diagnostics(now)
            }
        }(g)
    }
    wg.Wait()
    if d:=r.diagnostics(start.Add(time.Minute));d.OutboundEchoCacheEntries!=0{
        t.Fatalf("concurrent TTL pruning left live map entries: %+v",d)
    }
}
