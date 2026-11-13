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
  // A Direct-mode client Hello still needs an Echo Reply even when
  // the foreign host was previously using Reverse.
  if crypto.sec.region=="foreign" && sproto!=0 {sproto=8}
 }
 _=emitEcho(conn,peer,sproto,id,sequence,body)
}

// Encrypt each large-message fragment independently, so the outer IPv4
// packet remains <=1200 bytes without relying on kernel IP fragmentation.
// A complete MyMsg is reconstructed and authenticated at the far receiver.
func sendAuthenticatedParts(id, sequence int, conn icmp.PacketConn, peer *net.IPAddr,
    proto int, data []byte, crypto *CryptoConfig, msgType uint32, udpData bool) error {
    parts, err := splitAuthenticatedMessage(data)
    if err != nil { return err }
    if udpData && crypto.UDPParity && msgType == uint32(MyMsg_DATA) {
        parts = appendBoundedUDPParity(parts, time.Now())
    }
    for _, plain := range parts {
        encrypted, err := crypto.Encrypt(plain)
        if err != nil { return err }
        sendEncryptedICMP(id,sequence,conn,peer,proto,encrypted,crypto,msgType)
    }
    if len(parts) > 1 { icmpFragmentedDatagrams.Add(1) }
    return nil
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

    // A fully authenticated session may segment before encryption, avoiding
    // an oversized ciphertext and kernel IP fragmentation. While negotiating,
    // retain the existing whole-message pending queue; FlushPendingICMP will
    // segment the queued message only after authentication succeeds.
    if cryptoConfig != nil && cryptoConfig.sec != nil &&
        cryptoConfig.ICMPSegmentation && cryptoConfig.SecureReady() &&
        len(mb) > icmpMaxSecurePlaintext {
        if err := sendAuthenticatedParts(id,sequence,conn,server,sproto,mb,cryptoConfig,msgType,tcpmode==0); err != nil {
            if errors.Is(err,ErrSecureNegotiation) && msgType==uint32(MyMsg_DATA) {
                cryptoConfig.sec.queuePacket(pendingICMP{raw:mb,peer:server,id:id,seq:sequence,proto:sproto})
            } else {
                loggo.Error("sendICMP fragment error: %s",err)
            }
        }
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

	sendEncryptedICMP(id,sequence,conn,server,sproto,mb,cryptoConfig,msgType)
}

// isReflectedReversePoll detects a Linux Echo Reply that copies the 36-byte
// authenticated foreign-origin PTR4 request verbatim. It is not a secure
// control frame (PTH4) or encrypted application DATA (PTD4).
// The receiver must first enforce its pinned-IP policy before calling this.
func isReflectedReversePoll(crypto *CryptoConfig, icmpType byte, data []byte) bool {
    return crypto!=nil && crypto.sec!=nil && crypto.sec.region=="foreign" &&
        icmpType==0 && len(data)==reverseProbeBytes &&
        (stdbytes.Equal(data[:len(reverseProbeMagic)],reverseProbeMagic[:]) ||
         stdbytes.Equal(data[:len(reverseSwitchMagic)],reverseSwitchMagic[:]))
}

// Unlike PTR4 reflections, PTD4 Echo Replies can also be genuine encrypted
// peer DATA. Only suppress an Echo Reply that exactly matches the full
// ciphertext and ICMP ID/sequence of a recently transmitted request.
// Call this only after the paired source-IP check.
func isReflectedReverseDataEcho(crypto *CryptoConfig, icmpType byte, id,seq int, data []byte,now time.Time) bool {
    return crypto!=nil && crypto.sec!=nil && crypto.sec.region=="foreign" &&
        crypto.reverse!=nil && icmpType==0 &&
        len(data)>=len(secureDataMagic) &&
        stdbytes.Equal(data[:len(secureDataMagic)],secureDataMagic[:]) &&
        crypto.reverse.filterReflectedDataEcho(id,seq,data,now)
}

// Keep reflection classification separate from the DATA-only traffic hint.
// PING is tracked for kernel-reflection filtering, but never raises the
// adaptive poll frequency reserved for real QUIC application DATA.
func reverseEchoKindForMessage(msgType uint32) reverseEchoKind {
    switch msgType {
    case uint32(MyMsg_DATA): return reverseEchoDATA
    case uint32(MyMsg_PING): return reverseEchoPING
    default: return reverseEchoOther
    }
}

// Only genuine encrypted application DATA may accelerate Reverse polling.
// Idle keepalive PING, KICK, and handshake controls never create a PTW4
// wake burst: the baseline 1Hz timer already provides their opportunity.
func shouldWakeReverseFromMessage(msgType uint32) bool {
    return msgType==uint32(MyMsg_DATA)
}

// Send an already-encrypted payload without re-wrapping MyMsg or allocating
// a second session sequence. Used for draining authenticated pending packets.
func sendEncryptedICMP(id, sequence int, conn icmp.PacketConn, peer *net.IPAddr, proto int, encrypted []byte, crypto *CryptoConfig, msgType uint32) {
 if peer==nil||len(encrypted)==0{return}
 if useReverse(crypto) {
  if crypto.sec.region=="iran" {
   now:=time.Now()
   queued:=crypto.reverse.enqueue(encrypted,now)
   if queued && shouldWakeReverseFromMessage(msgType) &&
       crypto.SecureReady() && crypto.reverse.allowBacklogWake(now) {
       // This single signed hint is generated only for genuine queued
       // encrypted DATA. It carries no user content and cannot change
       // direction, AEAD keys or the Smart Rotation state machine.
       if hint,err:=crypto.reverse.makeQueueHint(now);err==nil && len(hint)>0 {
           if emitEcho(conn,peer,8,id,sequence,hint) {
               crypto.reverse.noteBacklogWakeSent()
           }
       }
   }
   return
  }
  proto=8
 }
 // Track ALL encrypted Foreign-origin Echo Requests, including PING.
 // Only app DATA can accelerate BBR/QUIC return-ACK polling.
 tracked:=useReverse(crypto) && crypto!=nil &&
    crypto.sec!=nil && crypto.sec.region=="foreign" && proto==8 &&
    len(encrypted)>=len(secureDataMagic) &&
    stdbytes.Equal(encrypted[:len(secureDataMagic)],secureDataMagic[:])
 var signature reverseSentEchoSignature
 var registeredAt time.Time
 if tracked {
    kind:=reverseEchoKindForMessage(msgType)
    // Stage before socket write: Linux may reflect before WriteTo returns.
    signature,registeredAt=crypto.reverse.stageOutboundEcho(id,sequence,encrypted,kind,time.Now())
 }
 if emitEcho(conn,peer,proto,id,sequence,encrypted) {
    if tracked && msgType==uint32(MyMsg_DATA) {
        crypto.reverse.noteOutboundFrame(time.Now())
    }
 } else if tracked {
    crypto.reverse.cancelOutboundDataEcho(signature,registeredAt)
 }
}

// Flush only when both peers finished their authenticated ephemeral exchange.
// The 2 MiB bounded queue and TTL prevent stale UDP/QUIC replay after outages.
func FlushPendingICMP(conn icmp.PacketConn, crypto *CryptoConfig) {
 if crypto==nil||crypto.sec==nil||!crypto.SecureReady(){return}
 packets:=crypto.sec.drainPending(time.Now())
 for i,p:=range packets{
  if crypto.ICMPSegmentation && len(p.raw)>icmpMaxSecurePlaintext {
   if err:=sendAuthenticatedParts(p.id,p.seq,conn,p.peer,p.proto,p.raw,crypto,uint32(MyMsg_DATA),false);err!=nil {
    for _,unsent:=range packets[i:] {crypto.sec.pushBack(unsent)}
    return
   }
   continue
  }
  encrypted,err:=crypto.Encrypt(p.raw)
  if err!=nil {
   // A parallel recovery may have started after we drained the queue.
   // Requeue the remainder, preserving expiry and accounting for drops.
   for _,unsent:=range packets[i:] {crypto.sec.pushBack(unsent)}
   return
  }
  sendEncryptedICMP(p.id,p.seq,conn,p.peer,p.proto,encrypted,crypto,uint32(MyMsg_DATA))
 }
}

// Maximal ICMPv4 datagrams can exceed the former 10,240-byte receive
// buffer when application UDP datagrams are large. Without this, Linux
// truncation could yield an AEAD failure or drop an otherwise valid packet.
const icmpReadBufferBytes = 65535

// Preserve the established single-service receive behavior unchanged.
func recvICMP(workResultLock *sync.WaitGroup, exit *atomic.Bool, conn icmp.PacketConn, recv chan<- *Packet, cryptoConfig *CryptoConfig, udpMode ...bool) {
    recvICMPWithMixedUDP(workResultLock,exit,conn,recv,nil,nil,cryptoConfig,udpMode...)
}

// Multi-Port retains the original short UDP DATA queue independently of TCP
// and dedicates a bounded third lane to authenticated control traffic.
func recvICMPWithMixedUDP(workResultLock *sync.WaitGroup, exit *atomic.Bool, conn icmp.PacketConn, recv chan<- *Packet, udpRecv chan *Packet, controlRecv chan<- *Packet, cryptoConfig *CryptoConfig, udpMode ...bool) {

	defer common.CrashLog()

	(*workResultLock).Add(1)
	defer (*workResultLock).Done()

	bytes := make([]byte, icmpReadBufferBytes)
    var fragmented authenticatedReassembler
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
            // Linux commonly reflects a received Echo Request with a
            // second, kernel-generated Echo Reply. These PTR4 reflections
            // are NOT session ciphertext and must never be passed to AEAD.
            if isReflectedReversePoll(cryptoConfig,bytes[0],payloadData) {
                if cryptoConfig.reverse!=nil {cryptoConfig.reverse.noteReflectedProbe()}
                continue
            }
            // PTD4 itself is not a reason to drop a reply: Iran's authentic
            // encrypted DATA/QUIC ACKs also start with PTD4. Reject only
            // an exact reflection of our own recent outbound ciphertext.
            if isReflectedReverseDataEcho(cryptoConfig,bytes[0],echoId,echoSeq,payloadData,now) {
                continue
            }
            // PTQ4 is a root-HMAC-authenticated queue-depth/age wake.
            // PTW4 remains supported for compatibility. Both are strictly
            // informational and never count as Reverse path-switch proofs.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                int(bytes[0])==8 &&
                (stdbytes.HasPrefix(payloadData,reverseWakeMagic[:]) ||
                 stdbytes.HasPrefix(payloadData,reverseQueueHintMagic[:])) {
                if useReverse(cryptoConfig) && cryptoConfig.SecureReady() {
                    if stdbytes.HasPrefix(payloadData,reverseQueueHintMagic[:]) {
                        if cryptoConfig.reverse.authenticateQueueHint(payloadData,now) {
                            cryptoConfig.reverse.noteAuthenticatedBacklogWake(now)
                        }
                    } else if cryptoConfig.reverse.authenticateBacklogWake(payloadData,now) {
                        cryptoConfig.reverse.noteAuthenticatedBacklogWake(now)
                    }
                }
                continue
            }
            // The local kernel can reflect our Iran-origin signed requests.
            // Never treat PTQ4/PTW4 reflections as encrypted application DATA.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==0 &&
                ((len(payloadData)==reverseProbeBytes &&
                  stdbytes.HasPrefix(payloadData,reverseWakeMagic[:])) ||
                 (len(payloadData)==reverseQueueHintBytes &&
                  stdbytes.HasPrefix(payloadData,reverseQueueHintMagic[:]))) {
                continue
            }
            // Only Direct-first AUTO may request a PTX4 Direct takeover.
            // A fresh root-HMACed, anti-replay verified Iranian request
            // receives a matched PTB4 Echo Reply. Retrying a lost ACK is
            // safe after Foreign has already selected Direct.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                int(bytes[0])==8 && stdbytes.HasPrefix(payloadData,directSwitchMagic[:]) {
                if cryptoConfig.SecureReady() &&
                    cryptoConfig.reverse.authenticateDirectSwitchProbe(payloadData,now) {
                    selected,authorized:=cryptoConfig.reverse.allowSignedDirectTakeover()
                    if authorized {
                        ack:=cryptoConfig.reverse.makeSwitchAck(payloadData,directSwitchAckMagic)
                        if len(ack)>0 && emitEcho(conn,peer,0,echoId,echoSeq,ack) &&
                            selected==ICMPReverse {
                            cryptoConfig.reverse.rotateKeepingSession(ICMPDirect,now,"preferred_direct_recovered")
                        }
                    }
                }
                continue
            }
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==0 && stdbytes.HasPrefix(payloadData,directSwitchAckMagic[:]) {
                if cryptoConfig.SecureReady() &&
                    cryptoConfig.reverse.acceptDirectSwitchProof(echoId,echoSeq,payloadData,now) {
                    cryptoConfig.reverse.rotateKeepingSession(ICMPDirect,now,"preferred_direct_recovered")
                }
                continue
            }
            // Linux may reflect the locally sent PTX4 Echo Request; it
            // cannot masquerade as the authenticated PTB4 acknowledgment.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==0 && stdbytes.HasPrefix(payloadData,directSwitchMagic[:]) {
                continue
            }
            // Foreign switches to Reverse only on a matched HMACed PTA4
            // acknowledgement of the switch request, never on a PTR4
            // proof or timer alone. Application keys stay unchanged.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                int(bytes[0])==0 && stdbytes.HasPrefix(payloadData,reverseSwitchAckMagic[:]) {
                // A pinned, root-MAC authenticated PTA4 may safely
                // change the ICMP initiator before an AEAD session exists
                // if Direct-first initial pairing could never complete.
                // It does not mark the application session authenticated.
                if (cryptoConfig.SecureReady() ||
                    cryptoConfig.reverse.preference==ICMPAutoDirect) &&
                    cryptoConfig.reverse.acceptReverseSwitchProof(echoId,echoSeq,payloadData,now) &&
                    cryptoConfig.reverse.rotateKeepingSession(ICMPReverse,now,"verified_reverse_available") {
                    // Immediately offer a matching Echo Request so Iran's
                    // reverse FIFO can start draining without a 10s wait.
                    sendForeignPoll(conn,peer,0x42a5,(echoSeq+1)&0xffff,cryptoConfig,now,true)
                }
                continue
            }
            // A low-rate Direct check is sent by Iran while Reverse
            // remains the preferred authenticated user transport.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                int(bytes[0])==8 && stdbytes.HasPrefix(payloadData,directProbeMagic[:]) {
                if cryptoConfig.reverse.authenticateDirectProbe(payloadData,now) {
                    proof:=cryptoConfig.reverse.makeDirectProof(payloadData)
                    _=emitEcho(conn,peer,0,echoId,echoSeq,proof)
                }
                continue
            }
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==0 && stdbytes.HasPrefix(payloadData,directProofMagic[:]) {
                cryptoConfig.reverse.acceptDirectProof(echoId,echoSeq,payloadData,now)
                continue
            }
            // Suppress only the foreign kernel's exact PTC4 auto-echo;
            // it is not a cryptographic proof of userspace reachability.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==0 && stdbytes.HasPrefix(payloadData,directProbeMagic[:]) {
                continue
            }
            // Reverse health proofs are unrelated to AEAD DATA: validate
            // them against the exact paired challenge, Echo ID/sequence and
            // root-key MAC. This does not authenticate or switch a session.
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                int(bytes[0])==0 &&
                (stdbytes.HasPrefix(payloadData,reverseProofMagic[:]) ||
                 stdbytes.HasPrefix(payloadData,reverseFallbackProofMagic[:])) {
                cryptoConfig.reverse.acceptProof(echoId,echoSeq,payloadData,now)
                continue
            }
            if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="iran" &&
                int(bytes[0])==8 &&
                (stdbytes.HasPrefix(payloadData,reverseProbeMagic[:]) ||
                 stdbytes.HasPrefix(payloadData,reverseSwitchMagic[:])) {
                valid,switchRequest:=cryptoConfig.reverse.authenticateProbeWithSwitch(payloadData,now)
                if valid {
                    if !switchRequest && !useReverse(cryptoConfig) {
                        // Authenticated userspace proof of the Reverse reply
                        // path while the existing Direct AEAD remains live.
                        // One extra reply per 10s maximum, not per poll.
                        if cryptoConfig.reverse.allowDirectPathProof(now) {
                            proof:=cryptoConfig.reverse.makeProof(payloadData,now,cryptoConfig.sec.lastPeerTraffic())
                            _=emitEcho(conn,peer,0,echoId,echoSeq,proof)
                        }
                    } else {
                        startReverseHandshake(conn,peer,echoId,echoSeq,cryptoConfig,now,switchRequest,payloadData)
                    }
                }
                continue
            }
            if stdbytes.HasPrefix(payloadData,secureControlMagic[:]) {
                response,err:=cryptoConfig.ReceiveSecureControl(payloadData,now)
                if err==nil {
                    // The first verified ClientHello acknowledges the poll:
                    // only then may Foreign select the reverse direction.
                    if cryptoConfig.reverse!=nil && cryptoConfig.sec.region=="foreign" &&
                        controlType(payloadData)==helloClient {
                        if int(bytes[0])==0 {
                            cryptoConfig.reverse.choose(ICMPReverse,now)
                        } else if int(bytes[0])==8 {
                            cryptoConfig.reverse.choose(ICMPDirect,now)
                        }
                    }
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

        // AEAD validation comes BEFORE reassembly: unauthenticated sources
        // cannot consume fragment assembly memory, and each chunk is replay
        // protected. In Reverse mode every authenticated incoming Echo
        // Request must still offer an opportunity to return a queued ACK.
        payloadData, complete := fragmented.accept(payloadData, time.Now())
        if !complete {
            if cryptoConfig!=nil && cryptoConfig.sec!=nil &&
                cryptoConfig.sec.region=="iran" && useReverse(cryptoConfig) &&
                int(bytes[0])==8 {
                replyReverse(conn,icmpSrcToIPAddr(srcaddr),echoId,echoSeq,cryptoConfig)
            }
            continue
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
        if cryptoConfig!=nil && cryptoConfig.reverse!=nil &&
            cryptoConfig.sec!=nil && cryptoConfig.sec.region=="foreign" &&
            useReverse(cryptoConfig) && my.Type==int32(MyMsg_DATA) {
            cryptoConfig.reverse.noteUsefulFrame(time.Now())
        }
        packet := &Packet{my: my,
            src: icmpSrcToIPAddr(srcaddr),
            echoId: echoId, echoSeq: echoSeq}
        // TCP preserves the established fail-safe dispatcher behavior.
        // On UDP, forwarding seconds-old backlogged game/QUIC packets
        // increases latency. Bound the pending queue and drop ONLY UDP DATA
        // immediately on overflow; keep control messages on the safe path.
        latencySensitiveUDP := len(udpMode) > 0 && udpMode[0]
        if !enqueueAuthenticatedPacketByTransport(recv,udpRecv,packet,latencySensitiveUDP,controlRecv) {
            loggo.Error("ICMP dispatcher blocked for 3s; restarting receiver")
            return
        }
	}
}

type Packet struct {
	my        *MyMsg
	src       *net.IPAddr
	echoId    int
	echoSeq   int
	serviceID string // authenticated Multi-Port service identity, derived from Target alias
}

const (
	FRAME_MAX_SIZE int = 888
	FRAME_MAX_ID   int = 1000000
)
