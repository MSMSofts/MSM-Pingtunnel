package pingtunnel

// Authenticated auto encryption for one Iran-side Go client and one foreign Go
// server. Both peers benchmark independently, and each accepts either frame
// algorithm. No algorithm-selection prompts or independent config matching.

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "errors"
 "io"
 "sync/atomic"
 "time"

 "golang.org/x/crypto/chacha20poly1305"
 "golang.org/x/crypto/hkdf"
)

const (
 autoAES byte = 1
 autoXChaCha byte = 2
)
var autoMagic = [4]byte{'P','T','A','1'}

type autoCrypto struct {
 aes cipher.AEAD
 xchacha cipher.AEAD
 preferred byte
 prefix [8]byte
 counter atomic.Uint64
}

// Auto mode insists on 32 bytes of uniformly generated key material.
// Unlike legacy modes, never fall back to a short numeric key or weak KDF.
func newAutoCryptoConfig(input string) (*CryptoConfig, error) {
 raw, err := base64.StdEncoding.Strict().DecodeString(input)
 if err != nil || len(raw) != 32 {
  return nil, errors.New("auto encryption requires a base64-encoded 32-byte key shared by both servers")
 }
 derive := func(label string) ([]byte,error) {
  result:=make([]byte,32)
  _,err:=io.ReadFull(hkdf.New(sha256.New,raw,nil,[]byte(label)),result)
  return result,err
 }
 akey,err:=derive("pingtunnel-auto-v1/aes256gcm")
 if err!=nil{return nil,err}
 xkey,err:=derive("pingtunnel-auto-v1/xchacha20poly1305")
 if err!=nil{return nil,err}
 block,err:=aes.NewCipher(akey)
 if err!=nil{return nil,err}
 aead,err:=cipher.NewGCM(block)
 if err!=nil{return nil,err}
 x,err:=chacha20poly1305.NewX(xkey)
 if err!=nil{return nil,err}
 c:=&autoCrypto{aes:aead,xchacha:x}
 if _,err=rand.Read(c.prefix[:]);err!=nil{return nil,err}
 c.preferred=autoBenchmark(aead,x)
 return &CryptoConfig{Mode:AUTO,Key:raw,auto:c},nil
}

// One-time startup measurement on the actual host CPU. The selected mode
// affects only outgoing packets. Incoming frames carry an authenticated cipher
// identifier so even machines choosing different algorithms interoperate.
func autoBenchmark(aesAEAD,xAEAD cipher.AEAD) byte {
 payload:=make([]byte,1024)
 if _,err:=rand.Read(payload);err!=nil{return autoAES}
 bench:=func(a cipher.AEAD) time.Duration {
  nonce:=make([]byte,a.NonceSize())
  output:=make([]byte,0,len(payload)+a.Overhead())
  var elapsed time.Duration
  for trial:=0;trial<3;trial++ {
   start:=time.Now()
   for i:=0;i<500;i++ {
    ciphertext:=a.Seal(output[:0],nonce,payload,nil)
    if _,err:=a.Open(nil,nonce,ciphertext,nil);err!=nil{return time.Hour}
   }
   elapsed+=time.Since(start)
  }
  return elapsed
 }
 aesTime:=bench(aesAEAD)
 xTime:=bench(xAEAD)
 // AES has 12-byte nonces vs 24 for XChaCha; only favor XChaCha when
 // measurably faster (>~10%), avoiding arbitrary flips from benchmark noise.
 if xTime < aesTime*9/10 {return autoXChaCha}
 return autoAES
}

// Frame: "PTA1" || algorithm(1 byte) || nonce || ciphertext || tag(16).
// Header (including algorithm identifier) is authenticated as AEAD AAD.
// Old plaintext or legacy unframed encryption is rejected, not downgraded.
func (c *autoCrypto) encrypt(data []byte) ([]byte,error) {
 var a cipher.AEAD
 var nonce []byte
 switch c.preferred {
 case autoAES:
  a=c.aes
  n:=c.counter.Add(1)
  if n>0xffffffff{return nil,errors.New("AES-GCM nonce counter exhausted; rotate key")}
  nonce=make([]byte,12)
  copy(nonce,c.prefix[:])
  binary.BigEndian.PutUint32(nonce[8:],uint32(n))
 case autoXChaCha:
  a=c.xchacha
  nonce=make([]byte,a.NonceSize())
  if _,err:=rand.Read(nonce);err!=nil{return nil,err}
 default:
  return nil,errors.New("invalid auto encryption algorithm")
 }
 header:=[]byte{autoMagic[0],autoMagic[1],autoMagic[2],autoMagic[3],c.preferred}
 output:=make([]byte,0,len(header)+len(nonce)+len(data)+a.Overhead())
 output=append(output,header...)
 output=append(output,nonce...)
 output=a.Seal(output,nonce,data,header)
 return output,nil
}

func (c *autoCrypto) decrypt(packet []byte) ([]byte,error) {
 if len(packet)<5 || packet[0]!=autoMagic[0] || packet[1]!=autoMagic[1] ||
    packet[2]!=autoMagic[2] || packet[3]!=autoMagic[3] {
  return nil,errors.New("packet is not an authenticated auto-encryption frame")
 }
 var a cipher.AEAD
 switch packet[4] {
 case autoAES:a=c.aes
 case autoXChaCha:a=c.xchacha
 default:return nil,errors.New("unknown cipher identifier")
 }
 if len(packet)<5+a.NonceSize()+a.Overhead(){
  return nil,errors.New("truncated authenticated frame")
 }
 nonce:=packet[5:5+a.NonceSize()]
 return a.Open(nil,nonce,packet[5+a.NonceSize():],packet[:5])
}
