package pingtunnel

import (
    "bytes"
    "testing"
    "time"
)

func TestReverseBacklogWakeReducesIdleFirstPacketLatency(t *testing.T) {
    start:=time.Unix(1890000000,0)
    root:=bytes.Repeat([]byte{0x72},32)
    iran,err:=newReverseTransport(ICMPAuto,root,start)
    if err!=nil{t.Fatal(err)}
    foreign,err:=newReverseTransport(ICMPAuto,root,start)
    if err!=nil{t.Fatal(err)}

    if period:=foreign.pollPeriod(start,0,true);period!=time.Second{
        t.Fatalf("idle poll changed unexpectedly: %s",period)
    }
    if iran.allowBacklogWake(start){
        t.Fatal("empty Reverse queue generated unsolicited wake")
    }
    if !iran.enqueue([]byte("AEAD-ciphertext"),start){t.Fatal("could not enqueue test DATA")}
    if !iran.allowBacklogWake(start){t.Fatal("first genuine DATA did not wake idle path")}
    if iran.allowBacklogWake(start.Add(499*time.Millisecond)){
        t.Fatal("one queued stream exceeded signed wake cooldown")
    }
    signed,e:=iran.makeBacklogWake(start)
    if e!=nil{t.Fatal(e)}
    invalid:=bytes.Clone(signed)
    invalid[len(invalid)-1]^=0x01
    if foreign.authenticateBacklogWake(invalid,start) {
        t.Fatal("invalid HMAC accepted as wake")
    }
    if !foreign.authenticateBacklogWake(signed,start){
        t.Fatal("authentic wake was rejected")
    }
    if foreign.authenticateBacklogWake(signed,start.Add(time.Millisecond)){
        t.Fatal("replayed wake accepted")
    }
    if !foreign.noteAuthenticatedBacklogWake(start){
        t.Fatal("verified wake not accepted")
    }
    select {
    case <-foreign.pollWakeup:
    default:
        t.Fatal("no immediate poller notification")
    }
    if foreign.noteAuthenticatedBacklogWake(start.Add(100*time.Millisecond)){
        t.Fatal("wake burst rate limit failed")
    }
    if got:=foreign.pollPeriod(start.Add(100*time.Millisecond),0,true);got!=reverseFastPollPeriod{
        t.Fatalf("woken queue should poll in %s, got %s",reverseFastPollPeriod,got)
    }
    if got:=foreign.pollPeriod(start.Add(reverseWakeBurst+time.Millisecond),0,true);got!=time.Second{
        t.Fatalf("expired hint kept idle link in high-rate polling: %s",got)
    }
    if iran.allowBacklogWake(start.Add(500*time.Millisecond))!=true{
        t.Fatal("cooldown did not permit retry while encrypted queue still exists")
    }
    iran.noteBacklogWakeSent()
    if _,ok:=iran.takeFrame(start.Add(600*time.Millisecond));!ok{
        t.Fatal("unexpected queue loss")
    }
    if iran.allowBacklogWake(start.Add(time.Second)){
        t.Fatal("empty queue kept generating wake notices")
    }
    if iran.direction()!=ICMPReverse||foreign.direction()!=ICMPReverse{
        t.Fatal("wake unexpectedly changed ICMP direction")
    }
    diagIran:=iran.diagnostics(start.Add(time.Second))
    diagForeign:=foreign.diagnostics(start.Add(100*time.Millisecond))
    if diagIran.BacklogWakeSent!=1||diagForeign.BacklogWakeAccepted!=1||
        diagForeign.BacklogWakeRateLimited!=1 {
        t.Fatalf("invalid wake counters iran=%+v foreign=%+v",diagIran,diagForeign)
    }
}

func TestReverseWakeCannotSwitchSmartRotationOrAuthenticateOldFrames(t *testing.T) {
    start:=time.Unix(1891000000,0)
    root:=bytes.Repeat([]byte{0x34},32)
    foreign,_:=newReverseTransport(ICMPAuto,root,start)
    iran,_:=newReverseTransport(ICMPAuto,root,start)
    signed,e:=iran.makeBacklogWake(start)
    if e!=nil{t.Fatal(e)}
    if !foreign.authenticateBacklogWake(signed,start){t.Fatal("valid HMAC wake rejected")}
    if !foreign.noteAuthenticatedBacklogWake(start){t.Fatal("verified Reverse wake rejected")}
    due:=start.Add(smartRotationInterval+time.Second)
    if foreign.takeSwitchRequest(due){
        t.Fatal("wakeup must not count as a signed two-way path proof")
    }
    if iran.shouldRequestDirectRotation(due,true) {
        t.Fatal("wakeup must not qualify scheduled Direct rotation")
    }
    if _,switchIntent:=foreign.authenticateProbeWithSwitch(signed,start);switchIntent{
        t.Fatal("wakeup must never be a switch intent")
    }
    if _,ok:=foreign.takeFrame(due);ok {
        t.Fatal("backlog notification must not insert user data")
    }
    if iran.direction()!=ICMPReverse||foreign.direction()!=ICMPReverse {
        t.Fatal("wakeup changed the preferred path")
    }
    // A different pairing key must reject the same wire packet.
    other,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{0x35},32),start)
    if other.authenticateBacklogWake(signed,start){t.Fatal("cross-pair wake accepted")}
}

func TestBacklogWakeBoundedDuringStream(t *testing.T){
    start:=time.Unix(1892000000,0)
    iran,_:=newReverseTransport(ICMPAuto,bytes.Repeat([]byte{7},32),start)
    count:=0
    for i:=0;i<1000;i++{
        now:=start.Add(time.Duration(i)*time.Millisecond)
        if !iran.enqueue([]byte("encrypted"),now){t.Fatal("bad enqueue")}
        if iran.allowBacklogWake(now){count++}
        _,_ = iran.takeFrame(now)
    }
    if count>3||count<1{t.Fatalf("wakeup hint rate exceeded 2/sec: %d",count)}
}
