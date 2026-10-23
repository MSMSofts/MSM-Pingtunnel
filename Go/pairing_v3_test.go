package pingtunnel

import(
 "bytes"
 "crypto/rand"
 "encoding/base64"
 "net"
 "testing"
)

func pairedTestKey(t *testing.T)string{
 t.Helper()
 bytes:=make([]byte,32)
 if _,err:=rand.Read(bytes);err!=nil{t.Fatal(err)}
 return base64.StdEncoding.EncodeToString(bytes)
}

func TestV3DirectionalAEADBothAlgorithms(t *testing.T){
 key:=pairedTestKey(t)
 iran,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 foreign,err:=NewCryptoConfig(AUTO,key)
 if err!=nil{t.Fatal(err)}
 if err=iran.BindRegion("iran");err!=nil{t.Fatal(err)}
 if err=foreign.BindRegion("foreign");err!=nil{t.Fatal(err)}
 for _,algorithm:=range []byte{autoAES,autoXChaCha}{
  iran.auto.preferred=algorithm
  foreign.auto.preferred=algorithm
  msg:=[]byte("payload from Iran")
  sealed,err:=iran.Encrypt(msg)
  if err!=nil{t.Fatal(err)}
  opened,err:=foreign.Decrypt(sealed)
  if err!=nil||!bytes.Equal(msg,opened){t.Fatalf("Iran->foreign cipher %d error %v",algorithm,err)}
  if _,err=iran.Decrypt(sealed);err==nil{t.Fatal("same physical direction should not decrypt its own transmission")}
  reply,err:=foreign.Encrypt([]byte("foreign response"))
  if err!=nil{t.Fatal(err)}
  plaintext,err:=iran.Decrypt(reply)
  if err!=nil||string(plaintext)!="foreign response"{t.Fatal("foreign->Iran message failed")}
 }
 if err:=iran.BindRegion("client");err==nil{t.Fatal("Go roles cannot replace physical region")}
}

func TestV3PeerAndDestinationPolicy(t *testing.T){
 server:=&Server{key:123}
 if err:=server.ApplyFixedForwardPolicy("203.0.113.5","127.0.0.1:8443",0);err!=nil{t.Fatal(err)}
 if err:=server.ApplyFixedForwardPolicy("203.0.113.5","0.0.0.0:8443",0);err==nil{t.Fatal("unsafe public destination accepted")}
 if err:=server.ApplyFixedForwardPolicy("203.0.113.5","127.0.0.1:0",0);err==nil{t.Fatal("zero target port accepted")}
 if err:=server.ApplyFixedForwardPolicy("203.0.113.5","127.0.0.1:8443",2);err==nil{t.Fatal("invalid transport accepted")}
 wrongPeer:=&Packet{
  src:&net.IPAddr{IP:net.ParseIP("203.0.113.6")},
  my:&MyMsg{Type:int32(MyMsg_KICK),Key:123,Target:"8.8.8.8:53"},
 }
 server.processPacket(wrongPeer)
 if wrongPeer.my.Target!="8.8.8.8:53"{t.Fatal("unauthorized peer packet was accepted")}
 wrongProtocol:=&Packet{
  src:&net.IPAddr{IP:net.ParseIP("203.0.113.5")},
  my:&MyMsg{Type:int32(MyMsg_DATA),Key:123,Tcpmode:1,Target:"8.8.8.8:53"},
 }
 server.processPacket(wrongProtocol)
 if wrongProtocol.my.Target!="8.8.8.8:53"{t.Fatal("mismatched TCP/UDP packet was accepted")}
 valid:=&Packet{
  src:&net.IPAddr{IP:net.ParseIP("203.0.113.5")},
  my:&MyMsg{Type:int32(MyMsg_KICK),Key:123,Target:"8.8.8.8:53"},
 }
 server.processPacket(valid)
 if valid.my.Target!="127.0.0.1:8443"{t.Fatal("server did not enforce local fixed destination")}
}
