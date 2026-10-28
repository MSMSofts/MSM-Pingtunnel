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

func reflectionTestDATA(seq byte) []byte {
    return append([]byte("PTD4"),bytes.Repeat([]byte{seq},112)...)
}

func TestReversePTD4ExactEchoReflectionNotAuthenticatedDATA(t *testing.T) {
    now:=time.Unix(1840000000,0)
    r,err:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{42},32),now)
    if err!=nil{t.Fatal(err)}
    c:=&CryptoConfig{sec:&secureSession{region:"foreign"},reverse:r}
    payload:=reflectionTestDATA(0x47)
    key,at:=r.stageOutboundDataEcho(17061,19410,payload,now)
    request,err:=(&icmp.Message{Type:ipv4.ICMPTypeEcho,Code:0,
        Body:&icmp.Echo{ID:17061,Seq:19410,Data:payload}}).Marshal(nil)
    if err!=nil{t.Fatal(err)}
    response,err:=(&icmp.Message{Type:ipv4.ICMPTypeEchoReply,Code:0,
        Body:&icmp.Echo{ID:17061,Seq:19410,Data:payload}}).Marshal(nil)
    if err!=nil{t.Fatal(err)}
    id:=int(binary.BigEndian.Uint16(response[4:6]))
    seq:=int(binary.BigEndian.Uint16(response[6:8]))
    if isReflectedReverseDataEcho(c,request[0],id,seq,request[8:],now.Add(2*time.Millisecond)){
        t.Fatal("foreign outgoing Echo Request must never be dropped as reflection")
    }
    before:=c.sec.stats().AuthenticationFailures
    if !isReflectedReverseDataEcho(c,response[0],id,seq,response[8:],now.Add(3*time.Millisecond)){
        t.Fatal("bit-for-bit echoed DATA must be discarded before AEAD decrypt")
    }
    if d:=r.diagnostics(now);d.ReflectedDataEchoes!=1 || d.OutboundEchoCacheEntries!=1{
        t.Fatalf("exact reflection not measured correctly: %+v",d)
    }
    if after:=c.sec.stats().AuthenticationFailures;after!=before{
        t.Fatal("filtered DATA reflection incorrectly increased authentication errors")
    }
    // Duplicate kernel echoes may still arrive; keep the digest until TTL.
    if !isReflectedReverseDataEcho(c,response[0],id,seq,response[8:],now.Add(4*time.Millisecond)){
        t.Fatal("duplicate kernel reflection was not filtered")
    }
    r.cancelOutboundDataEcho(key,at)
    if isReflectedReverseDataEcho(c,response[0],id,seq,response[8:],now.Add(5*time.Millisecond)){
        t.Fatal("failed send was not rolled back")
    }
}

func TestReversePTD4ReflectionMustMatchEntireCiphertextAndEchoNumbers(t *testing.T) {
    now:=time.Unix(1840000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{43},32),now)
    foreign:=&CryptoConfig{sec:&secureSession{region:"foreign"},reverse:r}
    iran:=&CryptoConfig{sec:&secureSession{region:"iran"},reverse:r}
    payload:=reflectionTestDATA(0x48)
    r.stageOutboundDataEcho(0x42a5,223,payload,now)
    cases:=[]struct{
        name string
        cfg *CryptoConfig
        typ byte
        id,seq int
        payload []byte
        matched bool
    }{
        {"exact",foreign,0,0x42a5,223,payload,true},
        {"different ciphertext same ICMP numbers",foreign,0,0x42a5,223,reflectionTestDATA(0x49),false},
        {"different ICMP ID",foreign,0,0x42a6,223,payload,false},
        {"different ICMP sequence",foreign,0,0x42a5,224,payload,false},
        {"foreign Echo Request",foreign,8,0x42a5,223,payload,false},
        {"Iran Echo Reply",iran,0,0x42a5,223,payload,false},
        {"control handshake",foreign,0,0x42a5,223,append([]byte("PTH4"),payload[4:]...),false},
        {"short PTD4",foreign,0,0x42a5,223,[]byte("PTD4"),false},
        {"no secure config",nil,0,0x42a5,223,payload,false},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            got:=isReflectedReverseDataEcho(tc.cfg,tc.typ,tc.id,tc.seq,tc.payload,now.Add(time.Second))
            if got!=tc.matched{t.Fatalf("filter=%v, want %v",got,tc.matched)}
        })
    }
    if isReflectedReverseDataEcho(foreign,0,0x42a5,223,payload,now.Add(reverseEchoTrackingWindow+time.Nanosecond)){
        t.Fatal("stale outgoing DATA signature was accepted after TTL")
    }
}

func TestReversePTD4TrackingBoundedEvictionAndFailureRollback(t *testing.T) {
    now:=time.Unix(1840000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{44},32),now)
    first:=reflectionTestDATA(0x01)
    firstKey,firstAt:=r.stageOutboundDataEcho(17061,7,first,now)
    r.cancelOutboundDataEcho(firstKey,firstAt)
    if r.filterReflectedDataEcho(17061,7,first,now.Add(time.Millisecond)){
        t.Fatal("failed send must not create a reflection match")
    }
    // Ring capacity is fixed: even sustained DATA bursts cannot grow memory.
    for i:=0;i<reverseEchoTrackingCapacity+1;i++{
        p:=reflectionTestDATA(0x55)
        binary.BigEndian.PutUint32(p[8:12],uint32(i))
        r.stageOutboundDataEcho(17061,i,p,now.Add(time.Duration(i)*time.Microsecond))
    }
    if d:=r.diagnostics(now);d.OutboundEchoCacheEntries>reverseEchoTrackingCapacity{
        t.Fatalf("unbounded outbound echo tracking: %+v",d)
    }
    oldest:=reflectionTestDATA(0x55)
    binary.BigEndian.PutUint32(oldest[8:12],0)
    if r.filterReflectedDataEcho(17061,0,oldest,now.Add(time.Second)){
        t.Fatal("evicted oldest frame still matched")
    }
    newest:=reflectionTestDATA(0x55)
    binary.BigEndian.PutUint32(newest[8:12],reverseEchoTrackingCapacity)
    if !r.filterReflectedDataEcho(17061,reverseEchoTrackingCapacity,newest,now.Add(time.Second)){
        t.Fatal("newly recorded frame not matched after bounded eviction")
    }
}

func TestReversePTD4EchoTrackingConcurrentSendAndReceive(t *testing.T) {
    now:=time.Unix(1840000000,0)
    r,_:=newReverseTransport(ICMPReverse,bytes.Repeat([]byte{45},32),now)
    const workers=8
    const perWorker=100
    var wg sync.WaitGroup
    for g:=0;g<workers;g++{
        wg.Add(1)
        go func(worker int){
            defer wg.Done()
            for i:=0;i<perWorker;i++{
                data:=reflectionTestDATA(0x68)
                binary.BigEndian.PutUint32(data[8:12],uint32(worker*perWorker+i))
                key,at:=r.stageOutboundDataEcho(17061,worker*perWorker+i,data,now)
                if !r.filterReflectedDataEcho(17061,worker*perWorker+i,data,now.Add(time.Millisecond)){
                    t.Errorf("concurrent exact echo not found: %d/%d",worker,i)
                }
                r.cancelOutboundDataEcho(key,at)
            }
        }(g)
    }
    wg.Wait()
    if d:=r.diagnostics(now);d.OutboundEchoCacheEntries!=0{
        t.Fatalf("failed to release tracking entries after concurrent cancellation: %+v",d)
    }
}
