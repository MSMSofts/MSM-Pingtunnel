package pingtunnel

import (
	"encoding/binary"
	stdbytes "bytes"
	"errors"
	"net"
	"sync/atomic"
	"sync"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"golang.org/x/net/icmp"
	"google.golang.org/protobuf/proto"
)

// Secure control frames use ICMP Echo with the same source/destination
// semantics as standard Pingtunnel, but contain no user data.
func sendSecureControl(id,sequence int,conn icmp.PacketConn,peer *net.IPAddr,sproto int,body []byte,crypto *CryptoConfig){
 if peer==nil||len(body)==0{return}
 if useReverse(crypto) {
  if crypto.sec.region=="iran" && sproto==8 {
   crypto.reverse.enqueue(body,time.Now())
   return
  }
  if crypto.sec.region=="foreign" {sproto=8}
 }
 _=emitEcho(conn,peer,sproto,id,sequence,body)
}

func sendICMP(id int, sequence int, conn icmp.PacketConn, server *net.IPAddr, target string,
	connId string, msgType uint32, data []byte, sproto int, rproto int, key int,
	tcpmode int, tcpmode_buffer_size int, tcpmode_maxwin int, tcpmode_resend_time int, tcpmode_compress int, tcpmode_stat int,
	timeout int, cryptoConfig *CryptoConfig) {

	m := &MyMsg{
		Id:                  connId,
		Type:                (int32)(msgType),
		Target:              target,
		Data:                data,
		Rproto:              (int32)(rproto),
		Key:                 (int32)(key),
		Tcpmode:             (int32)(tcpmode),
		TcpmodeBuffersize:   (int32)(tcpmode_buffer_size),
		TcpmodeMaxwin:       (int32)(tcpmode_maxwin),
		TcpmodeResendTimems: (int32)(tcpmode_resend_time),
		TcpmodeCompress:     (int32)(tcpmode_compress),
		TcpmodeStat:         (int32)(tcpmode_stat),
		Timeout:             (int32)(timeout),
		Magic:               (int32)(MyMsg_MAGIC),
	}

	mb, err := proto.Marshal(m)
	if err != nil {
		loggo.Error("sendICMP Marshal MyMsg error %s %s", server.String(), err)
		return
	}

	// Encrypt the marshaled data if encryption is enabled
	if cryptoConfig != nil {
        ciphertext, encryptErr := cryptoConfig.Encrypt(mb)
        if errors.Is(encryptErr,ErrSecureNegotiation) {
            if msgType==uint32(MyMsg_DATA) && cryptoConfig.sec!=nil {
                cryptoConfig.sec.queuePacket(pendingICMP{raw:mb,peer:server,id:id,seq:sequence,proto:sproto})
            }
            // The reverse leg has to respond to a real peer Echo Request.
            // Do NOT consume retransmission state on a local ticker and drop
            // the resulting Hello; that can starve the entire handshake.
            if useReverse(cryptoConfig)&&cryptoConfig.sec.region=="iran"{return}
            control,e:=cryptoConfig.SecureControl(time.Now())
            if e==nil&&len(control)>0 {
                 sendSecureControl(id,sequence,conn,server,sproto,control,cryptoConfig)
             }
            return
        }
		if encryptErr != nil {
			loggo.Error("sendICMP Encrypt error %s %s", server.String(), encryptErr)
			return
		}
        mb=ciphertext
	}

	sendEncryptedICMP(id,sequence,conn,server,sproto,mb,cryptoConfig)
}

// Send an already-encrypted payload without re-wrapping MyMsg or allocating
// a second session sequence. Used for draining authenticated pending packets.
func sendEncryptedICMP(id, sequence int, conn icmp.PacketConn, peer *net.IPAddr, proto int, encrypted []byte, crypto *CryptoConfig) {
 if peer==nil||len(encrypted)==0{return}
 if useReverse(crypto) {
  if crypto.sec.region=="iran" {
   crypto.reverse.enqueue(encrypted,time.Now())
   return
  }
  proto=8
 }
 _=emitEcho(conn,peer,proto,id,sequence,encrypted)
}

// Flush only when both peers finished their authenticated ephemeral exchange.
// The 2 MiB bounded queue and TTL prevent stale UDP/QUIC replay after outages.
func FlushPendingICMP(conn icmp.PacketConn, crypto *CryptoConfig) {
 if crypto==nil||crypto.sec==nil||!crypto.SecureReady(){return}
 packets:=crypto.sec.drainPending(time.Now())
 for i,p:=range packets{
  encrypted,err:=crypto.Encrypt(p.raw)
  if err!=nil {
   // A parallel recovery may have started after we drained the queue.
   // Requeue the remainder, preserving expiry and accounting for drops.
   for _,unsent:=range packets[i:] {crypto.sec.pushBack(unsent)}
   return
  }
  sendEncryptedICMP(p.id,p.seq,conn,p.peer,p.proto,encrypted,crypto)
 }
}

func recvICMP(workResultLock *sync.WaitGroup, exit *atomic.Bool, conn icmp.PacketConn, recv chan<- *Packet, cryptoConfig *CryptoConfig) {

	defer common.CrashLog()

	(*workResultLock).Add(1)
	defer (*workResultLock).Done()

	bytes := make([]byte, 10240)
	for !exit.Load() {
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, srcaddr, err := conn.ReadFrom(bytes)

		if err != nil {
            if exit.Load() { return }
            if nerr, ok := err.(net.Error); ok && nerr.Timeout() { continue }
            // A permanently broken socket must not silently spin forever.
            loggo.Error("fatal ICMP receive error: %v", err)
            return
        }

		if n < 8 { continue }

		echoId := int(binary.BigEndian.Uint16(bytes[4:6]))
		echoSeq := int(binary.BigEndian.Uint16(bytes[6:8]))

		// Extract the payload data
		payloadData := bytes[8:n]

        // Refuse control and data packets from any IP except the configured
        // paired VPS, before authentication, resource use, or Go dispatch.
        if cryptoConfig!=nil && cryptoConfig.sec!=nil {
            peer:=icmpSrcToIPAddr(srcaddr)
            if peer==nil||!cryptoConfig.SecurePeerAllowed(peer.IP){continue}
            now:=time.Now()
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==8 && stdbytes.HasPrefix(payloadData,reverseProbeMagic[:]) {
                if cryptoConfig.reverse.authenticateProbe(payloadData,now) {
                    startReverseHandshake(conn,peer,echoId,echoSeq,cryptoConfig,now)
                }
                continue
            }
            if stdbytes.HasPrefix(payloadData,secureControlMagic[:]) {
                response,err:=cryptoConfig.ReceiveSecureControl(payloadData,now)
                if err==nil {
                    replyType:=8
                    if cryptoConfig.sec.region=="foreign" && !useReverse(cryptoConfig) {replyType=0}
                    if cryptoConfig.sec.region=="iran" && useReverse(cryptoConfig) {replyType=0}
                    if len(response)>0 {
                        sendSecureControl(echoId,echoSeq,conn,peer,replyType,response,cryptoConfig)
                    } else if cryptoConfig.sec.region=="iran" && useReverse(cryptoConfig) && int(bytes[0])==8 {
                        replyReverse(conn,peer,echoId,echoSeq,cryptoConfig)
                    }
                }
                continue
            }
        }

		// Decrypt the data if encryption is enabled
		if cryptoConfig != nil {
			payloadData, err = cryptoConfig.Decrypt(payloadData)
			if err != nil {
				loggo.Debug("recvICMP Decrypt error: %s", err)
				continue
			}
		}

		my := &MyMsg{}
		err = proto.Unmarshal(payloadData, my)
		if err != nil {
			loggo.Debug("Unmarshal MyMsg error: %s", err)
			continue
		}

		if my.Magic != (int32)(MyMsg_MAGIC) {
			loggo.Debug("processPacket data invalid %s", my.Id)
			continue
		}

        if cryptoConfig!=nil && cryptoConfig.sec!=nil &&
            cryptoConfig.sec.region=="iran" && useReverse(cryptoConfig) && int(bytes[0])==8 {
            replyReverse(conn,icmpSrcToIPAddr(srcaddr),echoId,echoSeq,cryptoConfig)
        }
        packet := &Packet{my: my,
            src: icmpSrcToIPAddr(srcaddr),
            echoId: echoId, echoSeq: echoSeq}
        // A blocked dispatcher must not trap the sole ICMP receiver.
        select {
        case recv <- packet:
        default:
            stalled := time.NewTimer(3 * time.Second)
            select {
            case recv <- packet:
                stalled.Stop()
            case <-stalled.C:
                loggo.Error("ICMP dispatcher blocked for 3s; restarting receiver")
                return
            }
        }
	}
}

type Packet struct {
	my      *MyMsg
	src     *net.IPAddr
	echoId  int
	echoSeq int
}

const (
	FRAME_MAX_SIZE int = 888
	FRAME_MAX_ID   int = 1000000
)
