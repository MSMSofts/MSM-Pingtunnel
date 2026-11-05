package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

// Direct and Reverse scheduled handoffs must use the same ephemeral AEAD
// session and anti-replay window. Only the ICMP initiator role is rotated.
func TestReversePriorityNeverRotatesHealthyReverseToDirect(t *testing.T) {
    start:=time.Unix(1870000000,0)
    key:=pairedTestKey(t)
    iran,err:=NewCryptoConfig(AUTO,key);if err!=nil{t.Fatal(err)}
    foreign,err:=NewCryptoConfig(AUTO,key);if err!=nil{t.Fatal(err)}
    if err=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
    if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
    if err=iran.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
    if err=foreign.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
    iran.reverse.started=start
    foreign.reverse.started=start
    h1,err:=iran.SecureControl(start);if err!=nil{t.Fatal(err)}
    h2,err:=foreign.ReceiveSecureControl(h1,start);if err!=nil{t.Fatal(err)}
    h3,err:=iran.ReceiveSecureControl(h2,start);if err!=nil{t.Fatal(err)}
    h4,err:=foreign.ReceiveSecureControl(h3,start);if err!=nil{t.Fatal(err)}
    if _,err=iran.ReceiveSecureControl(h4,start);err!=nil{t.Fatal(err)}
    if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("Reverse handshake failed")}
    id:=iran.sec.keys.id
    if !useReverse(iran)||!useReverse(foreign){t.Fatal("AUTO must start on Reverse")}
    // Prove that Direct can work, yet Reverse is never preempted by a timer.
    for i:=0;i<2;i++ {
        at:=start.Add(time.Duration(60+i*60)*time.Second)
        if !iran.reverse.shouldProbeDirect(at,true){t.Fatal("Direct health check missing")}
        probe,e:=iran.reverse.makeDirectProbe(at);if e!=nil{t.Fatal(e)}
        iran.reverse.stageDirectProbe(300,10+i,probe,at)
        if !foreign.reverse.authenticateDirectProbe(probe,at){t.Fatal("signed Direct probe rejected")}
        reply:=foreign.reverse.makeDirectProof(probe)
        if !iran.reverse.acceptDirectProof(300,10+i,reply,at.Add(10*time.Millisecond)){
            t.Fatal("healthy Direct path proof rejected")
        }
    }
    for _, elapsed:=range []time.Duration{0,60*time.Second,3*time.Hour,7*time.Hour,24*time.Hour} {
        at:=start.Add(elapsed)
        if iran.reverse.rotationDue(at)||iran.reverse.shouldRequestDirectRotation(at,true) {
            t.Fatalf("Reverse must not be time-rotated to Direct after %s",elapsed)
        }
        if !useReverse(iran)||!useReverse(foreign){t.Fatal("healthy Reverse path unexpectedly switched")}
        if iran.sec.keys.id!=id || foreign.sec.keys.id!=id {t.Fatal("healthy session renegotiated")}
    }
    payload,e:=iran.Encrypt([]byte("steady-reverse-gaming-udp"));if e!=nil{t.Fatal(e)}
    decoded,e:=foreign.Decrypt(payload)
    if e!=nil||string(decoded)!="steady-reverse-gaming-udp"{t.Fatalf("Reverse payload lost: %v",e)}
    if iran.reverse.diagnostics(start.Add(24*time.Hour)).ScheduledRotations!=0 {
        t.Fatal("rotation counter incremented without an actual handoff")
    }
}

func TestReverseReturnPreservesEncryptedSessionAndFIFO(t *testing.T) {
    start:=time.Unix(1870300000,0)
    key:=pairedTestKey(t)
    iran,_:=NewCryptoConfig(AUTO,key)
    foreign,_:=NewCryptoConfig(AUTO,key)
    _=iran.BindRegion("iran");_=foreign.BindRegion("foreign")
    _=iran.BindICMPDirection("auto");_=foreign.BindICMPDirection("auto")
    iran.reverse.started=start
    foreign.reverse.started=start
    h1,_:=iran.SecureControl(start)
    h2,err:=foreign.ReceiveSecureControl(h1,start);if err!=nil{t.Fatal(err)}
    h3,err:=iran.ReceiveSecureControl(h2,start);if err!=nil{t.Fatal(err)}
    h4,err:=foreign.ReceiveSecureControl(h3,start);if err!=nil{t.Fatal(err)}
    if _,err=iran.ReceiveSecureControl(h4,start);err!=nil{t.Fatal(err)}
    originalID:=iran.sec.keys.id

    // Simulate an authenticated Direct fallback with the established keys.
    // The separate test covers failure-triggered Direct rekey negotiation.
    switched:=start.Add(100*time.Second)
    if !iran.reverse.rotateKeepingSession(ICMPDirect,switched,"test_failover") ||
       !foreign.reverse.rotateKeepingSession(ICMPDirect,switched,"test_failover") {
        t.Fatal("fixture failed to enter Direct")
    }
    probeTimes:=[]time.Time{switched.Add(40*time.Second),switched.Add(50*time.Second)}
    for i,at:=range probeTimes {
        probe,_:=foreign.reverse.makeProbe(at)
        id,seq:=0x42a5,500+i
        foreign.reverse.stageProbe(id,seq,probe,at)
        valid,sw:=iran.reverse.authenticateProbeWithSwitch(probe,at)
        if !valid||sw||!iran.reverse.allowDirectPathProof(at){t.Fatal("reverse return probe invalid")}
        if !foreign.reverse.acceptProof(id,seq,iran.reverse.makeProof(probe),at.Add(15*time.Millisecond)){
            t.Fatal("Reverse return proof missing")
        }
    }
    at:=switched.Add(65*time.Second)
    if !foreign.reverse.takeSwitchRequest(at){t.Fatal("healthy Reverse not restored from Direct")}
    p,_:=foreign.reverse.makeSwitchProbe(at)
    foreign.reverse.stageReverseSwitch(0x42a5,606,p,at)
    valid,request:=iran.reverse.authenticateProbeWithSwitch(p,at)
    if !valid||!request {t.Fatal("PT S4 request invalid")}
    if !iran.reverse.rotateKeepingSession(ICMPReverse,at,"preferred_reverse_recovered") {
        t.Fatal("Iran did not move to Reverse")
    }
    ack:=iran.reverse.makeSwitchAck(p,reverseSwitchAckMagic)
    if !foreign.reverse.acceptReverseSwitchProof(0x42a5,606,ack,at.Add(20*time.Millisecond)){
        t.Fatal("PTA4 recovery ACK invalid")
    }
    if !foreign.reverse.rotateKeepingSession(ICMPReverse,at.Add(20*time.Millisecond),"preferred_reverse_recovered") {
        t.Fatal("Foreign did not move to Reverse")
    }
    if iran.sec.keys.id!=originalID||foreign.sec.keys.id!=originalID {
        t.Fatal("preferred recovery unexpectedly reset encryption keys")
    }
    msg,err:=iran.Encrypt([]byte("responsive-game"));if err!=nil{t.Fatal(err)}
    if !iran.reverse.enqueue(msg,at){t.Fatal("failed to queue recovered Reverse DATA")}
    out,ok:=iran.reverse.takeFrame(at.Add(time.Millisecond))
    if !ok{t.Fatal("lost recovered queue DATA")}
    data,err:=foreign.Decrypt(out.data)
    if err!=nil||string(data)!="responsive-game" {t.Fatalf("return-to-reverse data corrupt: %v",err)}
    if iran.reverse.diagnostics(at).PreferredReverseReturns!=1 ||
       foreign.reverse.diagnostics(at).PreferredReverseReturns!=1 {
        t.Fatal("reverse preferred returns not counted")
    }
}

func TestSmartRotationOneWayPathDoesNotTriggerTimedSwitch(t *testing.T) {
    start:=time.Unix(1871000000,0)
    secret:=bytes.Repeat([]byte{0x91},32)
    iran,_:=newReverseTransport(ICMPAuto,secret,start)
    foreign,_:=newReverseTransport(ICMPAuto,secret,start)
    due:=start.Add(3*time.Hour)
    if iran.shouldRequestDirectRotation(due,true) {t.Fatal("no Direct proof, no switch")}
    if !iran.shouldProbeDirect(due.Add(-time.Minute),true){t.Fatal("Direct check missing")}
    // A PTC4 REQUEST reaching Foreign without a matching PDA4 REPLY
    // does not demonstrate return-path health.
    probe,_:=iran.makeDirectProbe(due.Add(-time.Minute))
    iran.stageDirectProbe(31,9,probe,due.Add(-time.Minute))
    if !foreign.authenticateDirectProbe(probe,due.Add(-time.Minute)){t.Fatal("auth test")}
    if iran.shouldRequestDirectRotation(due.Add(time.Minute),true) {t.Fatal("one-way Direct proof switched path")}
    if iran.direction()!=ICMPReverse||foreign.direction()!=ICMPReverse {
        t.Fatal("scheduled timer alone changed the selected route")
    }
    if !iran.rotateKeepingSession(ICMPDirect,due.Add(time.Minute),"forced-test") {
        t.Fatal("test setup failed")
    }
    if foreign.takeSwitchRequest(due.Add(3*time.Hour)) {
        t.Fatal("unproven Reverse return path forced takeover")
    }
}
func TestSmartRotationPreservesReverseEncryptedFIFO(t *testing.T) {
    start:=time.Unix(1872000000,0)
    r,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{3},32),start)
    at:=start.Add(3*time.Hour)
    if !r.enqueue([]byte("ciphertext-A"),at.Add(-time.Second)) ||
       !r.enqueue([]byte("ciphertext-B"),at.Add(-500*time.Millisecond)) {
        t.Fatal("could not enqueue")
    }
    if !r.rotateKeepingSession(ICMPDirect,at,"smart_rotation_to_direct"){t.Fatal("rotation failed")}
    a,ok:=r.takeFrame(at)
    if !ok||string(a.data)!="ciphertext-A"{t.Fatalf("lost first queued packet: %q",a.data)}
    b,ok:=r.takeFrame(at)
    if !ok||string(b.data)!="ciphertext-B"{t.Fatalf("lost second queued packet: %q",b.data)}
    if r.diagnostics(at).QueueDrops!=0{t.Fatal("queued application packets dropped on clean rotation")}
}
