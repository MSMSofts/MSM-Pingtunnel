package pingtunnel

import (
    "sync"
    "sync/atomic"
)

// v3.3.24 had one ICMP reader/dispatcher for a single TCP or UDP service.
// Multi-Port previously put every UDP service into ONE 256-slot queue and
// every TCP service into ONE 10000-slot queue. A saturated service could
// therefore crowd out unrelated services of the same protocol.
//
// Restore a separate pre-Multi-Port sized FIFO for EACH enabled service.
// Keep one authenticated ICMP receiver and one independent control lane;
// never spin up competing raw ICMP receivers for the same encrypted session.
type legacyServiceDispatchLane struct {
    id       string
    udp      bool
    queue    chan *Packet
    drops    atomic.Uint64
}

type legacyServiceDispatch struct {
    lanes map[string]*legacyServiceDispatchLane
}

type serviceDispatchLaneStatus struct {
    Protocol string `json:"protocol"`
    Queued   int    `json:"queued"`
    Capacity int    `json:"capacity"`
    Drops    uint64 `json:"drops"`
}

var activeServiceDispatch atomic.Pointer[legacyServiceDispatch]

func newLegacyServiceDispatch(protocolByService map[string]int) *legacyServiceDispatch {
    dispatch:=&legacyServiceDispatch{lanes:make(map[string]*legacyServiceDispatchLane,len(protocolByService))}
    for id,mode:=range protocolByService {
        udp:=mode==0
        dispatch.lanes[id]=&legacyServiceDispatchLane{
            id:id,udp:udp,
            queue:make(chan *Packet,packetQueueCapacity(udp)),
        }
    }
    return dispatch
}

func (d *legacyServiceDispatch) lane(serviceID string,mode int32) *legacyServiceDispatchLane {
    if d==nil {return nil}
    found:=d.lanes[serviceID]
    if found==nil || found.udp!=(mode==0) {return nil}
    return found
}

// Called by the single decrypted ICMP receive goroutine. Enqueue is
// nonblocking so one saturated TCP service cannot stop receiving UDP/control
// for every other service. For UDP this is EXACT v3.3.24 FIFO/drop-INCOMING:
// previously accepted datagrams are never evicted or reordered.
//
// TCP retains FrameMgr's retransmission support on overload. In an actual
// single-service v3.3.24 process a full TCP queue instead waits up to 3s;
// reproducing that blocking wait in this shared ICMP reader would freeze
// the other 11 services, so per-service bounded admission is intentional.
func (l *legacyServiceDispatchLane) admit(packet *Packet) bool {
    if l==nil {return false}
    select {
    case l.queue<-packet:
        return true
    default:
        l.drops.Add(1)
        if l.udp {
            udpIngressOverflowDrops.Add(1)
        } else {
            tcpIngressOverflowDrops.Add(1)
        }
        return true
    }
}

// Immutable lane map: safe to snapshot from the health goroutine while all
// service dispatch goroutines are consuming the queues concurrently.
func (d *legacyServiceDispatch) snapshot() map[string]serviceDispatchLaneStatus {
    if d==nil {return nil}
    result:=make(map[string]serviceDispatchLaneStatus,len(d.lanes))
    for id,lane:=range d.lanes {
        protocol:="tcp"
        if lane.udp {protocol="udp"}
        result[id]=serviceDispatchLaneStatus{
            Protocol:protocol,Queued:len(lane.queue),
            Capacity:cap(lane.queue),Drops:lane.drops.Load(),
        }
    }
    return result
}

func (d *legacyServiceDispatch) start(stop <-chan int, wg *sync.WaitGroup,
    handler func(*Packet), exit *atomic.Bool) {
    if d==nil {return}
    // Register every worker before launch to avoid an Add/Wait race if a
    // process shuts down immediately after launching the ICMP receiver.
    wg.Add(len(d.lanes))
    for _,lane:=range d.lanes {
        lane:=lane
        go func(){
            defer wg.Done()
            defer failOnUnexpectedWorkerExit("per-service "+lane.id+" ICMP dispatch",exit)
            runMixedDispatchLane(stop,lane.queue,handler)
        }()
    }
}
