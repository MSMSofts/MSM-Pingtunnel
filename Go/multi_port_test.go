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
