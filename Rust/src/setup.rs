//! One setup for each VPS; region is identity, not an encryption key owner.
//! The root pairing key is independent of client/server roles and survives
//! re-running setup or a future reversal of the ICMP initiation direction.
use crate::{apply_config, config_path, failure, get_number, get_string, prompt, root_required, store_config, validate, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{fs, io::Read, net::Ipv4Addr};

pub(crate) const SCHEMA: u64 = 3;

pub(crate) fn default_port(transport: &str) -> u16 {
    if transport == "udp" { 444 } else { 443 }
}

fn random_pair_key() -> Result<String> {
    let mut file = fs::File::open("/dev/urandom")?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    Ok(STANDARD.encode(bytes))
}

fn valid_pair_key(candidate: &str) -> bool {
    STANDARD.decode(candidate).map(|data| data.len() == 32 && STANDARD.encode(data) == candidate).unwrap_or(false)
}

fn existing_v3() -> Result<Option<Value>> {
    if !config_path().exists() { return Ok(None); }
    let cfg: Value = serde_json::from_slice(&fs::read(config_path())?)?;
    if cfg.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA) {
        return Err(failure("Old configuration is incompatible with v3. Back it up and remove it manually, then run 'pingtunnel setup'. No old key or port is imported."));
    }
    validate(&cfg)?;
    Ok(Some(cfg))
}

fn suggested_services()->Vec<Value> {
    let defaults:[(&str,u16);12]=[
        ("tcp",443),("udp",443),("tcp",2053),("udp",444),
        ("tcp",2083),("udp",1194),("tcp",2087),("udp",1701),
        ("tcp",2096),("udp",500),("tcp",8443),("udp",4500),
    ];
    defaults.iter().enumerate().map(|(i,(protocol,port))|
        json!({"id":format!("S{:02}",i+1),"protocol":protocol,
            "iran_port":port,"foreign_port":port,"enabled":false})
    ).collect()
}
fn legacy_multi_services(previous:&Value)->Vec<Value> {
    let mut rows=suggested_services();
    for row in rows.iter_mut() {row["enabled"]=json!(false);}
    let protocol=get_string(previous,"transport").unwrap_or("tcp");
    let port=get_number(previous,"port",443).unwrap_or(443);
    let index=if protocol=="udp"{1}else{0};
    rows[index]["iran_port"]=json!(port); rows[index]["foreign_port"]=json!(port);
    // No implicit binding of old ports, especially the common TCP 443.
    // Every enabled service must be explicitly chosen by the operator.
    rows[index]["enabled"]=json!(false);
    rows
}
fn configure_services(previous:Option<&Value>)->Result<Option<Vec<Value>>> {
    let existing=previous.and_then(|v|v.get("services")).and_then(Value::as_array);
    let default_choice=if existing.is_some(){"y"}else if previous.is_some(){"n"}else{"y"};
    println!("\nMulti-Port profile: up to 12 TCP/UDP service mappings.");
    println!("Each row maps an Iran ingress port to a Foreign 127.0.0.1 target port.");
    println!("All ports start DISABLED. Explicitly enable an intended TCP and UDP service; TCP 443 is never auto-bound.");
    println!("Defaults are suggestions. Enter accepts a row; edit it as protocol,iran_port,foreign_port,on/off.");
    let choice=prompt("Enable/configure Multi-Port? (y/n)",default_choice)?.to_ascii_lowercase();
    if !matches!(choice.as_str(),"y"|"yes") {return Ok(existing.map(|rows|rows.clone()));}
    let mut rows=if let Some(rows)=existing {rows.clone()}
        else if let Some(old)=previous {legacy_multi_services(old)}
        else {suggested_services()};
    let count:usize=prompt("Number of service slots (2..12)",&rows.len().to_string())?.parse()
        .map_err(|_|failure("service slot count must be 2..12"))?;
    if !(2..=12).contains(&count) {return Err(failure("service slot count must be 2..12"));}
    rows.truncate(count);
    let defaults=suggested_services();
    while rows.len()<count {rows.push(defaults[rows.len()].clone());}
    for index in 0..count {
        let id=rows[index].get("id").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(||format!("S{:02}",index+1));
        let protocol=rows[index].get("protocol").and_then(Value::as_str).unwrap_or("tcp");
        let iran=rows[index].get("iran_port").and_then(Value::as_u64).unwrap_or(443);
        let foreign=rows[index].get("foreign_port").and_then(Value::as_u64).unwrap_or(443);
        let enabled=if rows[index].get("enabled").and_then(Value::as_bool)==Some(true){"on"}else{"off"};
        let line=prompt(&format!("{id} [protocol,iran_port,foreign_port,on/off]"),&format!("{protocol},{iran},{foreign},{enabled}"))?;
        let parts:Vec<&str>=line.split(',').map(str::trim).collect();
        if parts.len()!=4 {return Err(failure(format!("{id}: enter protocol,iran_port,foreign_port,on/off")));}
        let protocol=parts[0].to_ascii_lowercase();
        if protocol!="tcp" && protocol!="udp" {return Err(failure(format!("{id}: protocol must be tcp or udp")));}
        let iran_port:u16=parts[1].parse().map_err(|_|failure(format!("{id}: invalid Iran port")))?;
        let foreign_port:u16=parts[2].parse().map_err(|_|failure(format!("{id}: invalid Foreign target port")))?;
        if iran_port==0 || foreign_port==0 {return Err(failure(format!("{id}: ports must be 1..65535")));}
        let active=match parts[3].to_ascii_lowercase().as_str() {
            "on"|"yes"|"y"|"true"|"1"=>true,"off"|"no"|"n"|"false"|"0"=>false,
            _=>return Err(failure(format!("{id}: enabled value must be on or off"))),
        };
        rows[index]=json!({"id":id,"protocol":protocol,"iran_port":iran_port,"foreign_port":foreign_port,"enabled":active});
    }
    Ok(Some(rows))
}

pub(crate) fn wizard() -> Result<()> {
    root_required()?;
    let previous = existing_v3()?;
    println!("\nPingtunnel — Unified Pair Setup (v3)");
    println!("Only two VPSs: Iran and Foreign. Automatic direct/reverse ICMP initiation.");
    println!("The shared 256-bit pairing key is NEVER bound to Client/Server roles.");

    // Q1: Physical identity (retained independently of ICMP client/server role).
    println!("1) Where is this VPS? 1 = Iran, 2 = Foreign");
    let previous_region = previous.as_ref().and_then(|v| get_string(v,"region")).unwrap_or("foreign");
    let region_default = if previous_region == "iran" { "1" } else { "2" };
    let region = match prompt("Region", region_default)?.as_str() {
        "1" => "iran",
        "2" => "foreign",
        _ => return Err(failure("Choose 1 or 2.")),
    };

    // Q2: Peer IP is significant on both servers; the Go server enforces it.
    let peer_default = previous.as_ref().and_then(|v| get_string(v,"peer_ip")).unwrap_or("");
    let peer = prompt("2) Opposite VPS public IPv4 address", peer_default)?;
    if peer.parse::<Ipv4Addr>().is_err() {return Err(failure("Enter the other VPS public IPv4 address (ICMPv4)."));}

    // Q3: Foreign host creates a 32-byte random key on FIRST setup, never
    // regenerates it on role changes. Iran enters precisely the same secret.
    let saved_key = previous.as_ref().and_then(|v| get_string(v,"pair_key")).map(str::to_owned);
    let pair_key = match (region, saved_key) {
        ("foreign", Some(key)) => {
            println!("3) Existing shared pairing key retained; no regeneration.");
            println!("Run sudo pingtunnel key only when you need to transfer the secret again.");
            key
        }
        ("foreign", None) => {
            let key = random_pair_key()?;
            println!("3) Generated strong 256-bit pairing key.");
            println!("Transfer this secret securely to the Iran VPS: {key}");
            key
        }
        ("iran", Some(key)) => {
            println!("3) Existing shared pairing key retained.");
            key
        }
        ("iran", None) => {
            println!("3) Enter the key generated by the FOREIGN VPS (input hidden).");
            let key = rpassword::prompt_password("Pairing key: ")?.trim().to_owned();
            if !valid_pair_key(&key) {return Err(failure("Pairing key must be canonical base64 for exactly 32 bytes."));}
            key
        }
        _ => unreachable!(),
    };

    let services=configure_services(previous.as_ref())?;
    let (transport,port):(String,u16)=if let Some(ref rows)=services {
        let first=rows.iter().find(|s|s.get("enabled").and_then(Value::as_bool)==Some(true))
            .ok_or_else(||failure("Enable at least one Multi-Port service"))?;
        // Retain the existing transport selector as the legacy queue-policy profile.
        let profile=previous.as_ref().and_then(|v|get_string(v,"transport")).unwrap_or("tcp").to_owned();
        let local=if region=="iran" {first["iran_port"].as_u64()} else {first["foreign_port"].as_u64()}
            .ok_or_else(||failure("invalid local service port"))?;
        (profile,u16::try_from(local)?)
    } else {
        // Single-service compatibility path remains unchanged.
        let default_transport=previous.as_ref().and_then(|v|get_string(v,"transport")).unwrap_or("tcp");
        let current=if default_transport=="udp"{"2"}else{"1"};
        println!("4) Legacy single transport: 1 = TCP, 2 = UDP (ICMP stays the tunnel).");
        let transport=match prompt("Transport",current)?.as_str() {
            "1"=>"tcp","2"=>"udp",_=>return Err(failure("Choose 1 (TCP) or 2 (UDP).")),
        };
        let prior_port=previous.as_ref().and_then(|v|v.get("port")).and_then(Value::as_u64);
        let suggested=match prior_port {
            Some(port) if default_transport!=transport && port==u64::from(default_port(default_transport))=>u64::from(default_port(transport)),
            Some(port)=>port,None=>u64::from(default_port(transport)),
        };
        let label=if region=="iran"{"5) Iran listener port"}else{"5) Foreign local VPN service port"};
        let port:u16=prompt(label,&suggested.to_string())?.parse().map_err(|_|failure("Port must be numeric."))?;
        if port==0{return Err(failure("Port must be in 1..65535."));}
        (transport.to_owned(),port)
    };

    let mut cfg = json!({
        "schema_version":SCHEMA,
        "region":region,
        "peer_ip":peer,
        "pair_key":pair_key,
        "transport":transport,
        "icmp_direction":previous.as_ref().and_then(|v|get_string(v,"icmp_direction")).unwrap_or("auto"),
        "port":port,
        "memory_mb":0,
        "autostart":true
    });
    if let Some(ref rows)=services { cfg["services"]=json!(rows); }
    // Preserve every existing performance, queue, timeout and security feature
    // setting across a Wizard rerun or Multi-Port activation.
    if let Some(ref old)=previous {
        for key in ["tcp_bs","tcp_mw","tcp_rst","udp_buf","timeout","icmp_segment","udp_fec","memory_mb","autostart"] {
            if let Some(value)=old.get(key) {cfg[key]=value.clone();}
        }
    }
    validate(&cfg)?;
    println!("\nSummary:");
    println!("  This server: {region} | Peer: {peer}");
    if let Some(ref rows)=services {
        let active=rows.iter().filter(|s|s["enabled"].as_bool()==Some(true)).count();
        println!("  Multi-Port: {} slots, {active} enabled; TCP + UDP; one shared encrypted ICMP session.",rows.len());
        println!("  Iran: open each enabled Iran ingress port in the matching TCP/UDP firewall rule.");
        println!("  Foreign: run each destination service on 127.0.0.1 at its configured target port; do not expose it publicly.");
    } else {
        println!("  Forwarding: {}:{} ({transport})", if region=="iran" { "Iran listen" } else { "Foreign loopback target" }, port);
    }
    println!("  Security: mandatory authenticated auto-AEAD; no plaintext fallback.");
    println!("  ICMP route policy: {}.",crate::route_policy_label(get_string(&cfg,"icmp_direction").unwrap_or("auto")));
    println!("  Auto performance: enabled on Iran; BB congestion in Go.");
    // Always save only after all five answers passed validation.
    store_config(&cfg)?;
    apply_config()?;
    println!("Configuration saved and service applied.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ports_are_role_local() {
        assert_eq!(default_port("tcp"),443);
        assert_eq!(default_port("udp"),444);
    }
    #[test]
    fn strong_keys_are_canonical_and_random() {
        let first=random_pair_key().unwrap();
        let second=random_pair_key().unwrap();
        assert!(valid_pair_key(&first));
        assert!(valid_pair_key(&second));
        assert_ne!(first,second);
        assert!(!valid_pair_key("password"));
        assert!(!valid_pair_key("123456"));
    }
    #[test]
    fn suggested_multi_port_profile_has_twelve_mixed_rows() {
        let rows=suggested_services();
        assert_eq!(rows.len(),12);
        assert_eq!(rows[0]["protocol"],"tcp");
        assert_eq!(rows[1]["protocol"],"udp");
        assert_eq!(rows.iter().filter(|row|row["enabled"].as_bool()==Some(true)).count(),0);
        assert_eq!(rows[0]["enabled"],false);
        assert_eq!(rows[1]["enabled"],false);
        assert_eq!(rows[2]["enabled"],false);
    }

    #[test]
    fn legacy_conversion_preserves_current_port_and_adds_complementary_protocol() {
        let mut old=json!({"transport":"udp","port":51820});
        let rows=legacy_multi_services(&old);
        assert_eq!(rows.len(),12);
        assert_eq!(rows[1]["iran_port"],51820);
        assert_eq!(rows[1]["foreign_port"],51820);
        assert_eq!(rows[1]["protocol"],"udp");
        assert_eq!(rows[0]["protocol"],"tcp");
        assert_eq!(rows[0]["enabled"],false);
        assert_eq!(rows.iter().filter(|row|row["enabled"].as_bool()==Some(true)).count(),0);
    }

}
