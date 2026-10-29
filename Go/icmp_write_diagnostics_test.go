package pingtunnel

import (
    "syscall"
    "testing"
)

func TestRecordICMPWriteResultAndMTUErrors(t *testing.T) {
    beforeWrites := icmpWriteErrors.Load()
    beforeSize := icmpMessageTooLong.Load()
    if !recordICMPWriteResult(48, 48, nil) {
        t.Fatal("complete socket write should succeed")
    }
    if recordICMPWriteResult(47, 48, nil) {
        t.Fatal("short write must fail")
    }
    if recordICMPWriteResult(0, 48, syscall.EMSGSIZE) {
        t.Fatal("oversized ICMP write must fail")
    }
    if recordICMPWriteResult(0, 48, syscall.EPERM) {
        t.Fatal("other kernel write errors must fail")
    }
    if got := icmpWriteErrors.Load() - beforeWrites; got != 3 {
        t.Fatalf("socket write failures: got %d want 3", got)
    }
    if got := icmpMessageTooLong.Load() - beforeSize; got != 1 {
        t.Fatalf("MTU write failures: got %d want 1", got)
    }
}
