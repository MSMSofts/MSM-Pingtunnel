package pingtunnel

import (
    "bytes"
    "testing"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

func TestReverseKernelEchoReflectionFilteredBeforeAEAD(t *testing.T) {
    start:=time.Unix(1820000000,0)
    root:=bytes.Repeat([]byte{0x3c},32)
    r,err:=newReverseTransport(ICMPAuto,root,start)
    if err!=nil {t.Fatal(err)}
    c:=&CryptoConfig{sec:&secureSession{region:"foreign"},reverse:r}
    // Exercise exactly the Echo Reply observed in production: 44 ICMP
    // bytes total (8-byte Echo header + 36-byte PTR4 request payload).
    probe,err:=r.makeProbe(start)
    if err!=nil{t.Fatal(err)}
    reply,err:=(&icmp.Message{Type:ipv4.ICMPTypeEchoReply,Code:0,
        Body:&icmp.Echo{ID:17061,Seq:26637,Data:probe}}).Marshal(nil)
    if err!=nil{t.Fatal(err)}
    if len(reply)!=44 {t.Fatalf("unexpected reflection length: %d",len(reply))}
    if !isReflectedReversePoll(c,reply[0],reply[8:]) {
        t.Fatal("kernel-generated reflected PTR4 poll reached decrypt path")
    }
    baseline:=c.sec.stats().AuthenticationFailures
    if isReflectedReversePoll(c,reply[0],reply[8:]){
        c.reverse.noteReflectedProbe()
    }
    if got:=c.reverse.diagnostics(start).ReflectedPolls;got!=1{
        t.Fatalf("filtered reflections should have independent counter: %d",got)
    }
    if got:=c.sec.stats().AuthenticationFailures;got!=baseline{
        t.Fatalf("reflection incorrectly increased AEAD errors: %d -> %d",baseline,got)
    }
}

func TestReverseEchoFilterCannotSuppressEncryptedPayloadOrControl(t *testing.T) {
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x5e},32),time.Now())
    foreign:=&CryptoConfig{sec:&secureSession{region:"foreign"},reverse:r}
    iran:=&CryptoConfig{sec:&secureSession{region:"iran"},reverse:r}
    cases:=[]struct{
        label string
        crypto *CryptoConfig
        typ byte
        data []byte
        blocked bool
    }{
        {"valid reflection",foreign,0,append([]byte("PTR4"),make([]byte,32)...),true},
        {"foreign request",foreign,8,append([]byte("PTR4"),make([]byte,32)...),false},
        {"other role",iran,0,append([]byte("PTR4"),make([]byte,32)...),false},
        {"secure data",foreign,0,append([]byte("PTD4"),make([]byte,80)...),false},
        {"secure control",foreign,0,append([]byte("PTH4"),make([]byte,64)...),false},
        {"short PTR4",foreign,0,[]byte("PTR4"),false},
        {"oversized PTR4",foreign,0,append([]byte("PTR4"),make([]byte,60)...),false},
        {"null config",nil,0,append([]byte("PTR4"),make([]byte,32)...),false},
    }
    for _,tc:=range cases{
        t.Run(tc.label,func(t *testing.T){
            if got:=isReflectedReversePoll(tc.crypto,tc.typ,tc.data);got!=tc.blocked{
                t.Fatalf("filter matched=%v want=%v",got,tc.blocked)
            }
        })
    }
}
