package pingtunnel

import (
 "bytes"
 "crypto/rand"
 "encoding/base64"
 "sync"
 "testing"
)

func autoTestKey(t *testing.T) string {
 t.Helper()
 data:=make([]byte,32)
 if _,err:=rand.Read(data);err!=nil{t.Fatal(err)}
 return base64.StdEncoding.EncodeToString(data)
}

func TestAutoModeCrossMachineCipherSelection(t *testing.T){
 key:=autoTestKey(t)
 client,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 server,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 tests:=[]struct{name string;id byte}{{"aes256gcm",autoAES},{"xchacha20poly1305",autoXChaCha}}
 for _,tc:=range tests{
  t.Run(tc.name,func(t *testing.T){
   client.auto.preferred=tc.id
   msg:=[]byte("Iran client -> foreign server, authenticated packet")
   ciphertext,err:=client.Encrypt(msg)
   if err!=nil{t.Fatal(err)}
   if ciphertext[4]!=tc.id{t.Fatal("wrong cipher ID")}
   // Peer is free to benchmark a completely different preferred mode.
   if tc.id==autoAES{server.auto.preferred=autoXChaCha}else{server.auto.preferred=autoAES}
   result,err:=server.Decrypt(ciphertext)
   if err!=nil{t.Fatal(err)}
   if !bytes.Equal(msg,result){t.Fatalf("plaintext mismatch: %q",result)}
   reply,err:=server.Encrypt([]byte("reply"))
   if err!=nil{t.Fatal(err)}
   if _,err:=client.Decrypt(reply);err!=nil{t.Fatal(err)}
   packet:=append([]byte{},ciphertext...)
   packet[len(packet)-1]^=0x80
   if _,err:=server.Decrypt(packet);err==nil{t.Fatal("AEAD tag tamper accepted")}
   packet=append([]byte{},ciphertext...)
   packet[4]=0xff
   if _,err:=server.Decrypt(packet);err==nil{t.Fatal("unknown cipher accepted")}
   packet=append([]byte{},ciphertext...)
   packet[4]=autoAES
   if tc.id!=autoAES{
    if _,err:=server.Decrypt(packet);err==nil{t.Fatal("unauthenticated cipher switch accepted")}
   }
  })
 }
}

func TestAutoKeyValidationAndNoDowngrade(t *testing.T){
 for _,invalid:=range []string{"","1234","example-password","MTIzNA=="}{
  if _,err:=NewCryptoConfig(AUTO,invalid);err==nil{t.Fatalf("accepted weak auto key %q",invalid)}
 }
 key:=autoTestKey(t)
 a,_:=NewCryptoConfig(AUTO,key)
 if _,err:=a.Decrypt([]byte("unencrypted packet"));err==nil{t.Fatal("accepted plaintext downgrade")}
 wrong,_:=NewCryptoConfig(AUTO,autoTestKey(t))
 pkt,_:=a.Encrypt([]byte("secret"))
 if _,err:=wrong.Decrypt(pkt);err==nil{t.Fatal("wrong key accepted")}
 for i:=0;i<len(pkt);i++{
  if _,err:=a.Decrypt(pkt[:i]);err==nil{t.Fatalf("accepted truncated frame len %d",i)}
 }
}

func TestAutoAESNoncesUniqueForConcurrentSenders(t *testing.T){
 key:=autoTestKey(t)
 c,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 c.auto.preferred=autoAES
 const workers=8
 const each=75
 results:=make(chan string,workers*each)
 var wg sync.WaitGroup
 for i:=0;i<workers;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   for j:=0;j<each;j++{
    ct,e:=c.Encrypt([]byte("pkt"))
    if e!=nil{t.Error(e);return}
    results<-string(ct[5:17])
   }
  }()
 }
 wg.Wait()
 close(results)
 seen:=map[string]bool{}
 for n:=range results{
  if seen[n]{t.Fatal("AES-GCM nonce reuse")}
  seen[n]=true
 }
 if len(seen)!=workers*each{t.Fatalf("got %d unique nonces",len(seen))}
}

func TestParseAutoMode(t *testing.T){
 mode,err:=ParseEncryptionMode("auto")
 if err!=nil || mode!=AUTO{t.Fatalf("mode=%v err=%v",mode,err)}
 if mode.String()!="auto"{t.Fatal("unexpected mode label")}
}
