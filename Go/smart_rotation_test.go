package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

// Direct and Reverse scheduled handoffs must use the same ephemeral AEAD
// session and anti-replay window. Only the ICMP initiator role is rotated.
func TestSmartRotationThreeHoursKeepsAuthenticatedTraffic(t *testing.T) {
    start:=time.Unix(1870000000,0)
    secret:=pairedTestKey(t)
    iran,err:=NewCryptoConfig(AUTO,secret);if err!=nil{t.Fatal(err)}
    foreign,err:=NewCryptoConfig(AUTO,secret);if err!=nil{t.Fatal(err)}
    if err=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
    if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
    if err=iran.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
    if err=foreign.BindICMPDirection("auto");err!=nil{t.Fatal(err)}
    // BindICMPDirection normally uses wall-clock time; use our deterministic
    // timeline here so the exact three-hour boundary is testable.
    iran.reverse.started=start
    foreign.reverse.started=start
    h1,err:=iran.SecureControl(start);if err!=nil{t.Fatal(err)}
    h2,err:=foreign.ReceiveSecureControl(h1,start);if err!=nil{t.Fatal(err)}
    h3,err:=iran.ReceiveSecureControl(h2,start);if err!=nil{t.Fatal(err)}
    h4,err:=foreign.ReceiveSecureControl(h3,start);if err!=nil{t.Fatal(err)}
    if _,err=iran.ReceiveSecureControl(h4,start);err!=nil{t.Fatal(err)}
    if !iran.SecureReady()||!foreign.SecureReady(){t.Fatal("failed initial reverse handshake")}
    before,err:=iran.Encrypt([]byte("before-rotation"))
    if err!=nil{t.Fatal(err)}
    decoded,err:=foreign.Decrypt(before)
    if err!=nil||string(decoded)!="before-rotation"{t.Fatalf("baseline secure payload failed: %v",err)}
    initialID:=iran.sec.keys.id
    if !useReverse(iran)||!useReverse(foreign){t.Fatal("first route should begin Reverse")}
    t3h:=start.Add(smartRotationInterval)
    if iran.reverse.shouldRequestDirectRotation(t3h,true) {
        t.Fatal("scheduled rotation ignored lack of healthy Direct proofs")
    }
    // Two distinct, paired Direct checks (no user-data switch).
    for i:=0;i<2;i++ {
        at:=t3h.Add(time.Duration(-120+i*60)*time.Second)
        if !iran.reverse.shouldProbeDirect(at,true){t.Fatal("failed to schedule Direct health check")}
        probe,e:=iran.reverse.makeDirectProbe(at);if e!=nil{t.Fatal(e)}
        id,seq:=17061,100+i
        iran.reverse.stageDirectProbe(id,seq,probe,at)
        if !foreign.reverse.authenticateDirectProbe(probe,at){t.Fatal("invalid authenticated Direct probe")}
        ack:=foreign.reverse.makeDirectProof(probe)
        if !iran.reverse.acceptDirectProof(id,seq,ack,at.Add(50*time.Millisecond)) {
            t.Fatal("authenticated Direct proof refused")
        }
        if iran.reverse.shouldRequestDirectRotation(at,true) {
            t.Fatal("premature rotation before three hours")
        }
    }
    if !iran.reverse.shouldRequestDirectRotation(t3h,true) {t.Fatal("eligible three-hour Direct rotation never started")}
    request,err:=iran.reverse.makeDirectSwitchProbe(t3h);if err!=nil{t.Fatal(err)}
    iran.reverse.stageDirectSwitch(17061,212,request,t3h)
    if !foreign.reverse.authenticateDirectSwitchProbe(request,t3h){t.Fatal("Direct switch request rejected")}
    if !foreign.reverse.rotateKeepingSession(ICMPDirect,t3h,"smart_rotation_to_direct"){
        t.Fatal("overseas endpoint did not stage Direct")
    }
    ack:=foreign.reverse.makeSwitchAck(request,directSwitchAckMagic)
    forged:=bytes.Clone(ack);forged[25]^=1
    if iran.reverse.acceptDirectSwitchProof(17061,212,forged,t3h.Add(20*time.Millisecond)){
        t.Fatal("forged Direct handoff accepted")
    }
    if !iran.reverse.acceptDirectSwitchProof(17061,212,ack,t3h.Add(80*time.Millisecond)){
        t.Fatal("paired Direct handoff ACK rejected")
    }
    if !iran.reverse.rotateKeepingSession(ICMPDirect,t3h.Add(80*time.Millisecond),"smart_rotation_to_direct"){
        t.Fatal("Iran did not commit Direct after matching ACK")
    }
    if useReverse(iran)||useReverse(foreign)||!iran.SecureReady()||!foreign.SecureReady(){
        t.Fatal("Direct rotation destroyed or mismatched active session")
    }
    if iran.sec.keys.id!=initialID || foreign.sec.keys.id!=initialID {
        t.Fatal("scheduled rotation incorrectly renegotiated AEAD keys")
    }
    payload,err:=foreign.Encrypt([]byte("active-quic-through-direct"))
    if err!=nil{t.Fatal(err)}
    decoded,err=iran.Decrypt(payload)
    if err!=nil||string(decoded)!="active-quic-through-direct"{t.Fatalf("Direct encrypted traffic interrupted: %v",err)}
    if iran.reverse.shouldRequestDirectRotation(t3h.Add(time.Second),true){
        t.Fatal("repeat Direct handoff while already Direct")
    }
    if foreign.reverse.takeSwitchRequest(t3h.Add(90*time.Second)) {
        t.Fatal("Reverse priority forcibly preempted three-hour Direct rotation")
    }
    t6h:=t3h.Add(smartRotationInterval+100*time.Millisecond)
    for i:=0;i<2;i++ {
        at:=t6h.Add(time.Duration(-20+i*10)*time.Second)
        probe,e:=foreign.reverse.makeProbe(at);if e!=nil{t.Fatal(e)}
        id,seq:=17061,300+i
        foreign.reverse.stageProbe(id,seq,probe,at)
        if !iran.reverse.authenticateProbe(probe,at){t.Fatal("Reverse challenge rejected")}
        proof:=iran.reverse.makeProof(probe)
        if !foreign.reverse.acceptProof(id,seq,proof,at.Add(50*time.Millisecond)){
            t.Fatal("Reverse return-path evidence rejected")
        }
    }
    if !foreign.reverse.takeSwitchRequest(t6h) {
        t.Fatal("eligible three-hour Reverse rotation never started")
    }
    reverseReq,err:=foreign.reverse.makeSwitchProbe(t6h);if err!=nil{t.Fatal(err)}
    foreign.reverse.stageReverseSwitch(0x42a5,405,reverseReq,t6h)
    valid,switchIntent:=iran.reverse.authenticateProbeWithSwitch(reverseReq,t6h)
    if !valid||!switchIntent{t.Fatal("signed Reverse takeover rejected")}
    if !iran.reverse.rotateKeepingSession(ICMPReverse,t6h,"smart_rotation_to_reverse"){
        t.Fatal("Iran did not stage Reverse")
    }
    reverseAck:=iran.reverse.makeSwitchAck(reverseReq,reverseSwitchAckMagic)
    if !foreign.reverse.acceptReverseSwitchProof(0x42a5,405,reverseAck,t6h.Add(70*time.Millisecond)){
        t.Fatal("Reverse handoff ACK rejected")
    }
    if !foreign.reverse.rotateKeepingSession(ICMPReverse,t6h.Add(70*time.Millisecond),"smart_rotation_to_reverse"){
        t.Fatal("Foreign failed to commit Reverse on matched ACK")
    }
    if !iran.SecureReady()||!foreign.SecureReady()||!useReverse(iran)||!useReverse(foreign){
        t.Fatal("Reverse recovery lost session or split direction")
    }
    if iran.sec.keys.id!=initialID||foreign.sec.keys.id!=initialID{
        t.Fatal("second scheduled switch unexpectedly reset session")
    }
    last,err:=iran.Encrypt([]byte("after-return-to-reverse"))
    if err!=nil{t.Fatal(err)}
    decoded,err=foreign.Decrypt(last)
    if err!=nil||string(decoded)!="after-return-to-reverse"{
        t.Fatalf("Reverse encrypted payload corrupted: %v",err)
    }
    iranDiag:=iran.reverse.diagnostics(t6h)
    foreignDiag:=foreign.reverse.diagnostics(t6h)
    if iranDiag.ScheduledRotations!=2 || foreignDiag.ScheduledRotations!=2{
        t.Fatalf("wrong rotation counters: Iran=%+v, Foreign=%+v",iranDiag,foreignDiag)
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
