package pingtunnel

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/binary"
    "fmt"
    "sync"
    "testing"
)

// Several simultaneous application flows can encrypt and authenticate over
// one Wire-v4 session. This also checks that reserving nonces and admitting
// replay counters remain atomic when the expensive AEAD work is unlocked.
// Fewer than 1024 packets are in flight so expected reordering never exceeds
// the protocol's fixed replay window.
func TestConcurrentSecureAEADMaintainsUniqueNoncesAndReplayWindow(t *testing.T) {
    sender,receiver := newSecurePair(t)
    const workers = 8
    const perWorker = 60
    start:=make(chan struct{})
    failed:=make(chan error,workers)
    var wg sync.WaitGroup
    for worker:=0;worker<workers;worker++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            <-start
            for j:=0;j<perWorker;j++ {
                plain:=[]byte(fmt.Sprintf("v4-parallel-%d-%d",id,j))
                frame,err:=sender.Encrypt(plain)
                if err!=nil {failed<-fmt.Errorf("encrypt worker %d: %w",id,err);return}
                decoded,err:=receiver.Decrypt(frame)
                if err!=nil {failed<-fmt.Errorf("decrypt worker %d: %w",id,err);return}
                if !bytes.Equal(decoded,plain) {failed<-fmt.Errorf("worker %d got wrong payload",id);return}
            }
        }(worker)
    }
    close(start)
    wg.Wait()
    close(failed)
    for err:=range failed {t.Error(err)}
    if t.Failed() {return}
    stats:=receiver.SecureStats()
    if stats.ReplayDrops!=0 || stats.AuthenticationFailures!=0 {
        t.Fatalf("concurrent valid traffic was rejected: %+v",stats)
    }
    // Reusing any authenticated ciphertext must still be rejected.
    replay,err:=sender.Encrypt([]byte("unique-final"))
    if err!=nil {t.Fatal(err)}
    if _,err=receiver.Decrypt(replay);err!=nil {t.Fatal(err)}
    if _,err=receiver.Decrypt(replay);err==nil {t.Fatal("duplicate accepted after concurrent traffic")}
}

// Microbenchmark for lock contention across simultaneous callers. Synthetic
// keys avoid including X25519 handshake time in the per-packet measurement.
// Run: go test -run '^$' -bench BenchmarkConcurrentSecureAEADEncrypt -benchmem
func BenchmarkConcurrentSecureAEADEncrypt(b *testing.B) {
    key:=bytes.Repeat([]byte{0x39},32)
    block,err:=aes.NewCipher(key)
    if err!=nil {b.Fatal(err)}
    aead,err:=cipher.NewGCM(block)
    if err!=nil {b.Fatal(err)}
    var id [16]byte
    binary.BigEndian.PutUint64(id[8:],1)
    session:=&secureSession{state:4,preferred:autoAES,
        keys:&sessionKeys{txAES:aead,id:id,txAESPrefix:[4]byte{1,2,3,4}}}
    b.SetBytes(512)
    b.ReportAllocs()
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        data:=make([]byte,512)
        for pb.Next() {
            if _,err:=session.encrypt(data);err!=nil {b.Error(err);return}
        }
    })
}
