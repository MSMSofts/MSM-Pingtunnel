package pingtunnel

import (
    "bytes"
    "encoding/binary"
    "net"
    "testing"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

// Direct, unlike Reverse, originates encrypted Echo Requests from Iran.
// The overseas kernel may send back an exact copy before the application
// returns its own independent direction-key encrypted Echo Reply.
func TestDirectEchoReflectionExactMatchKeepsRealPeerFrames(t *testing.T) {
    key:=pairedTestKey(t)
    iran,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    foreign,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    establishEphemeralPair(t,iran,foreign)
    for _,cfg:=range []*CryptoConfig{iran,foreign} {
        if err:=cfg.BindICMPDirection("direct");err!=nil {t.Fatal(err)}
    }
    if useReverse(iran) || useReverse(foreign) {t.Fatal("wrong route")}
    now:=time.Now()
    id,seq:=0x4122,177
    sent,err:=iran.Encrypt([]byte("video/QUIC outgoing ciphertext"))
    if err!=nil {t.Fatal(err)}
    signature,registered:=iran.reverse.stageOutboundEcho(id,seq,sent,reverseEchoDATA,now)
    request,err:=(&icmp.Message{Type:ipv4.ICMPTypeEcho,Body:&icmp.Echo{
        ID:id,Seq:seq,Data:sent,
    }}).Marshal(nil)
    if err!=nil {t.Fatal(err)}
    reflected,err:=(&icmp.Message{Type:ipv4.ICMPTypeEchoReply,Body:&icmp.Echo{
        ID:id,Seq:seq,Data:sent,
    }}).Marshal(nil)
    if err!=nil {t.Fatal(err)}
    frameID:=int(binary.BigEndian.Uint16(reflected[4:6]))
    frameSeq:=int(binary.BigEndian.Uint16(reflected[6:8]))
    errorsBefore:=iran.SecureStats().AuthenticationFailures
    if isReflectedEncryptedEcho(iran,request[0],frameID,frameSeq,request[8:],now.Add(time.Millisecond)) {
        t.Fatal("outbound Echo Request was classified as received reflection")
    }
    if !isReflectedEncryptedEcho(iran,reflected[0],frameID,frameSeq,reflected[8:],now.Add(time.Millisecond)) {
        t.Fatal("Iran Direct did not filter the overseas kernel's exact ciphertext reflection")
    }
    if got:=iran.SecureStats().AuthenticationFailures;got!=errorsBefore {
        t.Fatalf("filtering an exact reflection inflated AEAD failures: got %d want %d",got,errorsBefore)
    }
    if diag:=iran.reverse.diagnostics(now.Add(time.Millisecond));diag.DirectReflectedDataEchoes!=1 || diag.ReflectedDataEchoes!=0 {
        t.Fatalf("Direct reflection was not classified independently: %+v",diag)
    }
    if !iran.SecurePeerAllowed(net.ParseIP("203.0.113.5")) ||
        iran.SecurePeerAllowed(net.ParseIP("203.0.113.7")) {
        t.Fatal("paired peer IP gating must remain strict before reflection checks")
    }
    if opened,err:=foreign.Decrypt(sent);err!=nil||!bytes.Equal(opened,[]byte("video/QUIC outgoing ciphertext")) {
        t.Fatalf("foreign application DATA broken: %v",err)
    }
    legit,err:=foreign.Encrypt([]byte("real encrypted video ACK"))
    if err!=nil {t.Fatal(err)}
    validReply,err:=(&icmp.Message{Type:ipv4.ICMPTypeEchoReply,Body:&icmp.Echo{ID:id,Seq:seq,Data:legit}}).Marshal(nil)
    if err!=nil {t.Fatal(err)}
    if isReflectedEncryptedEcho(iran,validReply[0],id,seq,validReply[8:],now.Add(2*time.Millisecond)) {
        t.Fatal("legitimate peer Echo Reply was confused with our own request")
    }
    if opened,err:=iran.Decrypt(legit);err!=nil||string(opened)!="real encrypted video ACK" {
        t.Fatalf("legitimate Direct response was not authenticated: %v",err)
    }
    if isReflectedEncryptedEcho(foreign,reflected[0],id,seq,reflected[8:],now.Add(3*time.Millisecond)) {
        t.Fatal("Foreign Direct applied Iran-only reflection rule")
    }
    if isReflectedEncryptedEcho(iran,0,id+1,seq,sent,now.Add(3*time.Millisecond)) ||
       isReflectedEncryptedEcho(iran,0,id,seq+1,sent,now.Add(3*time.Millisecond)) {
        t.Fatal("ICMP Echo ID/sequence mismatch was suppressed")
    }
    altered:=bytes.Clone(sent)
    altered[len(altered)-1]^=1
    if isReflectedEncryptedEcho(iran,0,id,seq,altered,now.Add(3*time.Millisecond)) {
        t.Fatal("nonidentical ciphertext was suppressed")
    }
    if isReflectedEncryptedEcho(iran,0,id,seq,sent,now.Add(reverseEchoTrackingWindow+time.Millisecond)) {
        t.Fatal("stale outbound digest remained eligible")
    }
    iran.reverse.cancelOutboundDataEcho(signature,registered)
}

func TestDirectExactReflectionAllMessageTypesAndRollback(t *testing.T) {
    key:=pairedTestKey(t)
    cfg,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    if err=cfg.BindRegion("iran");err!=nil {t.Fatal(err)}
    if err=cfg.BindICMPDirection("direct");err!=nil {t.Fatal(err)}
    now:=time.Now()
    for i,kind:=range []reverseEchoKind{reverseEchoDATA,reverseEchoPING,reverseEchoOther} {
        body:=append([]byte("PTD4"),bytes.Repeat([]byte{byte(i+31)},64)...)
        id,seq:=0x5cc2,i+100
        sig,at:=cfg.reverse.stageOutboundEcho(id,seq,body,kind,now)
        if !isReflectedEncryptedEcho(cfg,0,id,seq,body,now.Add(time.Millisecond)) {
            t.Fatalf("Direct exact encrypted reflection not recognized for kind=%d",kind)
        }
        cfg.reverse.cancelOutboundDataEcho(sig,at)
        if isReflectedEncryptedEcho(cfg,0,id,seq,body,now.Add(2*time.Millisecond)) {
            t.Fatal("failed socket send remained eligible after rollback")
        }
    }
    d:=cfg.reverse.diagnostics(now.Add(time.Millisecond))
    if d.DirectReflectedDataEchoes!=1||d.DirectReflectedPingEchoes!=1||d.DirectReflectedOtherEchoes!=1 {
        t.Fatalf("wrong Direct reflected kind counters: %+v",d)
    }
    if d.ReflectedDataEchoes+d.ReflectedPingEchoes+d.ReflectedOtherEchoes!=0 {
        t.Fatal("Direct reflections contaminated Reverse counters")
    }
}

func TestAuthenticatedFailureTypesSeparatedFromEchoReflections(t *testing.T) {
    key:=pairedTestKey(t)
    iran,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    foreign,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    establishEphemeralPair(t,iran,foreign)
    good,err:=foreign.Encrypt([]byte("valid independent reply"))
    if err!=nil {t.Fatal(err)}
    invalid:=[]byte("no v4 framing")
    if _,err=iran.Decrypt(invalid);err==nil {t.Fatal("invalid format accepted")}
    wrongSession:=bytes.Clone(good)
    wrongSession[6]^=0x40
    if _,err=iran.Decrypt(wrongSession);err==nil {t.Fatal("wrong session accepted")}
    wrongTag:=bytes.Clone(good)
    wrongTag[len(wrongTag)-1]^=0x40
    if _,err=iran.Decrypt(wrongTag);err==nil {t.Fatal("bad AEAD tag accepted")}
    status:=iran.sec.status()
    if status.AuthFailures!=3 || status.AuthInvalidFormat!=1 ||
       status.AuthWrongSession!=1 || status.AuthTagFailures!=1 {
        t.Fatalf("authentication failure categories must be independently observable: %+v",status)
    }
    if _,err=iran.Decrypt(good);err!=nil {t.Fatalf("valid peer frame rejected after bad frames: %v",err)}
}

func TestHandshakeAuthenticationErrorsAreNotCountedAsAEADTags(t *testing.T) {
    key:=pairedTestKey(t)
    iran,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    foreign,err:=NewCryptoConfig(AUTO,key)
    if err!=nil {t.Fatal(err)}
    establishEphemeralPair(t,iran,foreign)
    forged:=controlBody(helloClient,[16]byte{1,2,3},[16]byte{},bytes.Repeat([]byte{7},32))
    forged=append(forged,bytes.Repeat([]byte{0},32)...)
    if _,err:=foreign.ReceiveSecureControl(forged,time.Now());err==nil {
        t.Fatal("unauthenticated reconnect control was accepted")
    }
    status:=foreign.sec.status()
    if status.AuthFailures!=1 || status.AuthControlFailures!=1 ||
       status.AuthTagFailures!=0 || status.AuthWrongSession!=0 {
        t.Fatalf("bad control MAC was misclassified as an application AEAD failure: %+v",status)
    }
    if !foreign.SecureReady() {t.Fatal("forged reconnect disrupted existing authenticated session")}
}
