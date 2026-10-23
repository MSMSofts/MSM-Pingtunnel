package pingtunnel

// Manager v3 fixed-destination policy for one Iran client and one foreign VPS.
// Peer IP is checked before the Go worker dispatch; forwarding can only reach
// the foreign VPS's loopback service port chosen in its own setup.
import(
 "errors"
 "net"
 "strconv"
)

func (s *Server) ApplyFixedForwardPolicy(peerIPv4,target string,tcp int)error{
 ip:=net.ParseIP(peerIPv4)
 if ip==nil || ip.To4()==nil || ip.IsUnspecified() || ip.IsLoopback(){
  return errors.New("peer IPv4 must be the actual Iran VPS address")
 }
 host,port,err:=net.SplitHostPort(target)
 if err!=nil{return err}
 if host!="127.0.0.1"{return errors.New("fixed target must be bound to foreign loopback 127.0.0.1")}
 n,err:=strconv.Atoi(port)
 if err!=nil || n<1 || n>65535{return errors.New("fixed target port must be 1..65535")}
 if tcp!=0 && tcp!=1{return errors.New("fixed tunnel transport must be TCP=1 or UDP=0")}
 if s.forwardConfig!=nil{return errors.New("fixed target mode does not allow upstream proxy overrides")}
 s.allowedPeer=ip.To4()
 s.fixedTarget=target
 s.forwardProtocol=tcp
 return nil
}
