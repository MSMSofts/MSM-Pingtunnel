package pingtunnel

import (
    "testing"
    "time"
)

func TestForeignReverseApplicationEchoSequencesAreIndependent(t *testing.T) {
    key:=pairedTestKey(t)
    foreign,err:=NewCryptoConfig(AUTO,key);if err!=nil{t.Fatal(err)}
    if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
    if err=foreign.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
    p:=&Server{cryptoConfig:foreign}
    if !useReverse(foreign){t.Fatal("AUTO failed to start Reverse")}
    firstID,firstSeq:=p.applicationEchoIdentity(100,7)
    secondID,secondSeq:=p.applicationEchoIdentity(100,7)
    if firstID!=0x42A5||secondID!=0x42A5||firstSeq==secondSeq {
        t.Fatalf("Reverse DATA reused Echo identity: (%d,%d) (%d,%d)",
          firstID,firstSeq,secondID,secondSeq)
    }
    if !foreign.reverse.choose(ICMPDirect,time.Now().Add(100*time.Second)) {
        t.Fatal("test could not enter Direct fallback")
    }
    directID,directSeq:=p.applicationEchoIdentity(100,7)
    if directID!=100||directSeq!=7{
        t.Fatalf("Direct response must retain request Echo identity, got (%d,%d)",
          directID,directSeq)
    }
    if !foreign.reverse.choose(ICMPReverse,time.Now().Add(200*time.Second)) {
        t.Fatal("test could not restore preferred Reverse")
    }
    resumedID,resumedSeq:=p.applicationEchoIdentity(100,7)
    if resumedID!=0x42A5||resumedSeq==secondSeq{
        t.Fatal("restored Reverse reused an old Echo Request sequence")
    }
}
