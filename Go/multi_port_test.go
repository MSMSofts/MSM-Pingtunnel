package pingtunnel

import "testing"

func TestValidatePortServicesMixedAndLimit(t *testing.T) {
    services := []PortService{
        {ID:"S01", Protocol:"tcp", IranPort:443, ForeignPort:443, Enabled:true},
        {ID:"S02", Protocol:"udp", IranPort:443, ForeignPort:8443, Enabled:true},
    }
    if err := validatePortServices(services); err != nil { t.Fatalf("valid mixed profile rejected: %v", err) }
    services[1].Enabled = false
    if err := validatePortServices(services); err == nil { t.Fatal("TCP-only profile accepted in combined mode") }
    services[1].Enabled = true
    services = append(services, PortService{ID:"S03",Protocol:"tcp",IranPort:443,ForeignPort:2053,Enabled:true})
    if err := validatePortServices(services); err == nil { t.Fatal("duplicate enabled TCP ingress accepted") }
    tooMany := make([]PortService, 13)
    for i:=range tooMany { tooMany[i]=PortService{ID:"S01",Protocol:"tcp",IranPort:1000+i,ForeignPort:2000+i,Enabled:true} }
    if err := validatePortServices(tooMany); err == nil { t.Fatal("more than 12 services accepted") }
}

func TestServiceAliasIsOpaqueAndStrict(t *testing.T) {
    if got := ServiceTarget("S12"); got != "msm-service:S12" { t.Fatalf("unexpected alias %q", got) }
    if id, ok := ParseServiceAlias("msm-service:S12"); !ok || id != "S12" { t.Fatalf("valid alias rejected: %q %v", id, ok) }
    for _, alias := range []string{"127.0.0.1:443","msm-service:S00","msm-service:S13","msm-service:../x"} {
        if _, ok := ParseServiceAlias(alias); ok { t.Fatalf("unsafe alias accepted: %q", alias) }
    }
}

func TestFirstEnabledPortService(t *testing.T) {
    services := []PortService{{ID:"S01",Protocol:"tcp",Enabled:false},{ID:"S02",Protocol:"udp",Enabled:true}}
    service, ok := FirstEnabledPortService(services)
    if !ok || service.ID != "S02" { t.Fatalf("wrong first enabled service: %+v %v", service, ok) }
}

func TestMultiForwardTargetCachedAndPinned(t *testing.T) {
    service := PortService{ID:"S02", Protocol:"udp", IranPort:53042, ForeignPort:54042, Enabled:true}
    got := newMultiForwardTarget(service)
    if got.id != "S02" || got.tcpMode != 0 || got.loopback != "127.0.0.1:54042" {
        t.Fatalf("unexpected cached UDP forwarding: %+v", got)
    }
    service.Protocol = "tcp"
    service.ForeignPort = 54443
    got = newMultiForwardTarget(service)
    if got.tcpMode != 1 || got.loopback != "127.0.0.1:54443" {
        t.Fatalf("unexpected cached TCP forwarding: %+v", got)
    }
}

func TestApplyMultiForwardPolicyRejectsUnauthorizedProfiles(t *testing.T) {
    profile := []PortService{
        {ID:"S01",Protocol:"tcp",IranPort:53041,ForeignPort:54041,Enabled:true},
        {ID:"S02",Protocol:"udp",IranPort:53041,ForeignPort:54041,Enabled:true},
    }
    for _, invalid := range []string{"", "127.0.0.1", "0.0.0.0", "invalid-host"} {
        s := &Server{}
        if err := s.ApplyMultiForwardPolicy(invalid,profile,1); err == nil {
            t.Fatalf("accepted invalid peer %q",invalid)
        }
    }
    s := &Server{}
    if err := s.ApplyMultiForwardPolicy("198.51.100.7",profile,1); err != nil {t.Fatal(err)}
    if len(s.forwardServices) != 2 {t.Fatalf("expected 2 aliases, got %d",len(s.forwardServices))}
    if _, ok := s.forwardServices["msm-service:S13"]; ok {t.Fatal("unknown alias accepted")}
    if _, ok := s.forwardServices["127.0.0.1:54041"]; ok {t.Fatal("raw destination accepted")}
    if got := s.forwardServices["msm-service:S02"]; got.tcpMode != 0 || got.loopback != "127.0.0.1:54041" {
        t.Fatalf("wrong UDP target: %+v",got)
    }
    if err := (&Server{}).ApplyMultiForwardPolicy("198.51.100.7",profile,2); err == nil {
        t.Fatal("accepted invalid existing queue profile")
    }
}
