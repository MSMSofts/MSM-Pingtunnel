package pingtunnel

import (
    "errors"
    "fmt"
    "net"
    "strconv"
    "strings"
    "time"

    "github.com/esrrhs/gohome/common"
    "github.com/esrrhs/gohome/loggo"
)

// PortService is one logical TCP or UDP ingress-to-loopback mapping.
// Both VPSs receive the same profile; each role uses only its local-side port.
type PortService struct {
    ID          string `json:"id"`
    Protocol    string `json:"protocol"`
    IranPort    int    `json:"iran_port"`
    ForeignPort int    `json:"foreign_port"`
    Enabled     bool   `json:"enabled"`
}

// multiForwardTarget stores the allowlisted target once at configuration load.
// High-throughput UDP receive paths must not format loopback addresses per packet.
type multiForwardTarget struct {
    id       string
    tcpMode  int
    loopback string
}

func newMultiForwardTarget(service PortService) multiForwardTarget {
    mode := 0
    if service.Protocol == "tcp" { mode = 1 }
    return multiForwardTarget{
        id: service.ID, tcpMode: mode,
        loopback: net.JoinHostPort("127.0.0.1", strconv.Itoa(service.ForeignPort)),
    }
}

// ServiceTarget returns the opaque target alias carried inside the existing
// authenticated Wire v4 MyMsg.Target field. It is never a dialable address.
func ServiceTarget(id string) string { return "msm-service:" + id }

func validServiceID(id string) bool {
    if len(id) != 3 || id[0] != 'S' { return false }
    n, err := strconv.Atoi(id[1:])
    return err == nil && n >= 1 && n <= 12 && fmt.Sprintf("S%02d", n) == id
}

func validatePortServices(services []PortService) error {
    if len(services) < 1 || len(services) > 12 {
        return errors.New("Multi-Port requires 1..12 service entries")
    }
    ids := make(map[string]bool, len(services))
    iranPorts := make(map[string]bool, len(services))
    foreignPorts := make(map[string]bool, len(services))
    enabled, tcpEnabled, udpEnabled := 0, false, false
    for _, service := range services {
        if !validServiceID(service.ID) { return fmt.Errorf("invalid service ID %q (use S01..S12)", service.ID) }
        if ids[service.ID] { return fmt.Errorf("duplicate service ID %s", service.ID) }
        ids[service.ID] = true
        if service.Protocol != "tcp" && service.Protocol != "udp" {
            return fmt.Errorf("%s protocol must be tcp or udp", service.ID)
        }
        if service.IranPort < 1 || service.IranPort > 65535 || service.ForeignPort < 1 || service.ForeignPort > 65535 {
            return fmt.Errorf("%s ports must be in 1..65535", service.ID)
        }
        if !service.Enabled { continue }
        enabled++
        if service.Protocol == "tcp" { tcpEnabled = true } else { udpEnabled = true }
        ik := service.Protocol + ":" + strconv.Itoa(service.IranPort)
        fk := service.Protocol + ":" + strconv.Itoa(service.ForeignPort)
        if iranPorts[ik] { return fmt.Errorf("duplicate enabled Iran %s port %d", service.Protocol, service.IranPort) }
        if foreignPorts[fk] { return fmt.Errorf("duplicate enabled Foreign %s port %d", service.Protocol, service.ForeignPort) }
        iranPorts[ik], foreignPorts[fk] = true, true
    }
    if enabled == 0 { return errors.New("at least one Multi-Port service must be enabled") }
    if !tcpEnabled || !udpEnabled { return errors.New("combined Multi-Port mode requires at least one enabled TCP and one enabled UDP service") }
    return nil
}

func hasEnabledUDPService(services []PortService) bool {
    for _, service := range services { if service.Enabled && service.Protocol == "udp" { return true } }
    return false
}

func FirstEnabledPortService(services []PortService) (PortService, bool) {
    for _, service := range services { if service.Enabled { return service, true } }
    return PortService{}, false
}

func (p *Client) SetPortServices(services []PortService) error {
    if err := validatePortServices(services); err != nil { return err }
    p.services = append([]PortService(nil), services...)
    // Do not change p.tcpmode: it continues to select the existing
    // dispatcher/queue profile chosen by the operator before Multi-Port.
    return nil
}

func (p *Client) startMultiPortListeners() error {
    p.multiTCPListeners = make(map[string]*net.TCPListener)
    p.multiUDPListeners = make(map[string]*net.UDPConn)
    cleanup := func() {
        for _, listener := range p.multiTCPListeners { _ = listener.Close() }
        for _, listener := range p.multiUDPListeners { _ = listener.Close() }
    }
    for _, service := range p.services {
        if !service.Enabled { continue }
        switch service.Protocol {
        case "tcp":
            listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: service.IranPort})
            if err != nil { cleanup(); return fmt.Errorf("listen TCP %d (%s): %w", service.IranPort, service.ID, err) }
            p.multiTCPListeners[service.ID] = listener
        case "udp":
            listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: service.IranPort})
            if err != nil { cleanup(); return fmt.Errorf("listen UDP %d (%s): %w", service.IranPort, service.ID, err) }
            if p.udpSocketBuffer > 0 {
                if err := listener.SetReadBuffer(p.udpSocketBuffer); err != nil { _ = listener.Close(); cleanup(); return fmt.Errorf("set UDP receive buffer for %s: %w", service.ID, err) }
                if err := listener.SetWriteBuffer(p.udpSocketBuffer); err != nil { _ = listener.Close(); cleanup(); return fmt.Errorf("set UDP send buffer for %s: %w", service.ID, err) }
            }
            p.multiUDPListeners[service.ID] = listener
        }
    }
    for _, service := range p.services {
        if !service.Enabled { continue }
        // Register workers before launching them, so Stop/Wait never races
        // an Add on a newly scheduled listener goroutine.
        p.workResultLock.Add(1)
        if service.Protocol == "tcp" {
            go p.acceptMultiTCP(service, p.multiTCPListeners[service.ID])
        } else {
            go p.acceptMultiUDP(service, p.multiUDPListeners[service.ID])
        }
    }
    loggo.Info("Multi-Port enabled: %d services (shared ICMP session; existing queue policy retained)", len(p.multiTCPListeners)+len(p.multiUDPListeners))
    return nil
}

func (p *Client) acceptMultiTCP(service PortService, listener *net.TCPListener) {
    defer common.CrashLog()
    defer failOnUnexpectedWorkerExit("Multi-Port TCP listener "+service.ID, &p.exit)
    defer p.workResultLock.Done()
    for !p.exit.Load() {
        _ = listener.SetDeadline(time.Now().Add(time.Second))
        conn, err := listener.AcceptTCP()
        if err != nil {
            if nerr, ok := err.(net.Error); ok && nerr.Timeout() { continue }
            if p.exit.Load() { return }
            loggo.Error("Multi-Port TCP accept %s: %v", service.ID, err)
            return
        }
        go p.acceptTcpConn(conn, ServiceTarget(service.ID), 1, service.ID)
    }
}

func (p *Client) acceptMultiUDP(service PortService, listener *net.UDPConn) {
    defer common.CrashLog()
    defer failOnUnexpectedWorkerExit("Multi-Port UDP listener "+service.ID, &p.exit)
    defer p.workResultLock.Done()
    bytes := make([]byte, udpMaxDatagramBytes)
    for !p.exit.Load() {
        _ = listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        n, srcaddr, truncated, err := readUDPDatagram(listener, bytes)
        if err != nil {
            if nerr, ok := err.(net.Error); ok && nerr.Timeout() { continue }
            if p.exit.Load() { return }
            loggo.Error("Multi-Port UDP read %s: %v", service.ID, err)
            return
        }
        if n <= 0 || truncated {
            if truncated { loggo.Info("drop truncated Multi-Port UDP datagram (%s)", service.ID) }
            continue
        }
        now := common.GetNowUpdateInSecond()
        addrKey := service.ID + "|" + srcaddr.String()
        clientConn := p.getClientConnByAddr(addrKey)
        if clientConn == nil {
            if p.maxconn > 0 && p.localIdToConnMapSize.Load() >= int64(p.maxconn) {
                loggo.Info("too many connections %d; drop UDP source %s on %s", p.localIdToConnMapSize.Load(), srcaddr, service.ID)
                continue
            }
            clientConn = &ClientConn{ipaddr: copyUDPAddr(srcaddr), id: common.UniqueId(), tcpmode: 0,
                udpListenConn: listener, serviceID: service.ID}
            p.addClientConn(clientConn.id, addrKey, clientConn)
        }
        clientConn.activeSendUnixNano.Store(now.UnixNano())
        sendICMP(p.id, p.nextSequence(), *p.conn, p.serverIP.Load(), ServiceTarget(service.ID), clientConn.id,
            uint32(MyMsg_DATA), bytes[:n], SEND_PROTO, RECV_PROTO, p.key,
            0, p.udpSocketBuffer, 0, 0, 0, 0, p.timeout, p.cryptoConfig)
        p.sendPacket.Add(1)
        p.sendPacketSize.Add(uint64(n))
        p.touchActivity()
    }
}

// ParseServiceAlias is intentionally strict; target aliases cannot smuggle
// hostnames or arbitrary network destinations into the Foreign dial path.
func ParseServiceAlias(alias string) (string, bool) {
    const prefix = "msm-service:"
    if !strings.HasPrefix(alias, prefix) { return "", false }
    id := strings.TrimPrefix(alias, prefix)
    return id, validServiceID(id)
}
