package pingtunnel

import "testing"

func TestReverseWakeIgnoresKeepalivesAndControl(t *testing.T) {
    if !shouldWakeReverseFromMessage(uint32(MyMsg_DATA)) {
        t.Fatal("application DATA must wake the authenticated Reverse poller")
    }
    for _, m:=range []uint32{uint32(MyMsg_PING), uint32(MyMsg_KICK)} {
        if shouldWakeReverseFromMessage(m) {
            t.Fatalf("non-DATA message %d accelerated Reverse polls",m)
        }
    }
}
