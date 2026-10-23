//! One-time setup wizard. Only the actual peer and service identities require
//! input; service tuning, systemd, restart and HA policy are automatic.

use crate::{
    apply_config, as_string, config_path, failure, get_string, prompt, root_required,
    store_config, Result,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};

fn new_key() -> Result<String> {
    let mut input = fs::File::open("/dev/urandom")?;
    let mut bytes = [0u8; 4];
    input.read_exact(&mut bytes)?;
    // Pingtunnel upstream limits the authentication key to 31 bits.
    // Never reuse the insecure 123456 example default.
    let value = u32::from_le_bytes(bytes) & 0x7fff_ffff;
    Ok(value.to_string())
}

fn valid_peer(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 &&
    !s.starts_with('-') &&
    !s.chars().any(|c| c.is_control() || c.is_whitespace() || c == '/')
}

fn valid_destination(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else { return false };
    valid_peer(host) && port.parse::<u16>().map(|p| p != 0).unwrap_or(false)
}

fn choose_role(current: &str) -> Result<&'static str> {
    println!("Choose this VPS role (only once, or when switching roles):");
    println!("  1) Foreign server / Pingtunnel Server");
    println!("  2) Iran server / Pingtunnel Client");
    let default = if current == "client" { "2" } else { "1" };
    let chosen = prompt("Role", default)?;
    match chosen.as_str() {
        "1" => Ok("server"),
        "2" => Ok("client"),
        _ => Err(failure("Choose 1 or 2.")),
    }
}

fn existing_config() -> Result<Option<Value>> {
    if !config_path().exists() {
        return Ok(None);
    }
    let old: Value = serde_json::from_slice(&fs::read(config_path())?)?;
    if !old.is_object() {
        return Err(failure("Existing configuration is invalid, not overwriting it."));
    }
    Ok(Some(old))
}

pub(crate) fn wizard() -> Result<()> {
    root_required()?;
    let old = existing_config()?;
    let initial = old.is_none();
    let mut cfg = old.unwrap_or_else(|| json!({
        "tcp": 1,
        "memory_mb": 0,
        "autostart": true
    }));
    println!("\n╔══════════════════════════════════════════════╗");
    println!("║       Pingtunnel — Automatic setup           ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("TCP tuning, systemd, health checks and restart are automatic.");
    println!("Only the remote address, shared key and actual destination are needed.");

    let role = choose_role(get_string(&cfg, "type").unwrap_or("server"))?;
    cfg["type"] = json!(role);
    if role == "server" {
        let key = cfg.get("key").and_then(as_string)
            .filter(|v| !v.is_empty())
            .unwrap_or(new_key()?);
        cfg["key"] = json!(key);
        cfg["autostart"] = json!(true);
        if let Some(map) = cfg.as_object_mut() {
            map.remove("ha"); // HA is client-side only.
        }
        println!("\nServer configuration ready.");
        println!("Share these details securely with the Iran-side client:");
        println!("  Authentication key: {key}");
        println!("  Server public IP/DNS: use the address assigned by your VPS provider.");
        println!("Do not publish the key in GitHub or logs.");
    } else {
        let existing_host = get_string(&cfg, "server").unwrap_or("");
        let host = prompt("Foreign Pingtunnel Server IP/DNS", existing_host)?;
        if !valid_peer(&host) {
            return Err(failure("A valid foreign server IP/DNS is required."));
        }
        cfg["server"] = json!(host);

        let existing_key = cfg.get("key").and_then(as_string);
        println!("Use the authentication key shown by the FOREIGN server setup.");
        let key = prompt(
            "Shared numeric key (Enter keeps the existing key)",
            ""
        )?;
        let key = if key.is_empty() {
            existing_key.ok_or_else(|| failure("The client needs the shared key from its server."))?
        } else {
            key
        };
        let numeric: u64 = key.parse().map_err(|_| failure("The shared key must be numeric."))?;
        if numeric > 2_147_483_647 {
            return Err(failure("Key must be <= 2147483647."));
        }
        cfg["key"] = json!(key);

        let target = prompt(
            "Destination host:port on foreign network",
            get_string(&cfg, "target").unwrap_or("127.0.0.1:443")
        )?;
        if !valid_destination(&target) {
            return Err(failure("Destination must be host:port (e.g. 127.0.0.1:443)."));
        }
        cfg["target"] = json!(target);

        if !cfg.get("l_port").and_then(Value::as_u64)
            .map(|n| (1..=65535).contains(&n)).unwrap_or(false)
        {
            cfg["l_port"] = json!(4455);
        }
        // TCP is the default transport of the forwarded service; UDP can be
        // selected later from the main menu without editing JSON by hand.
        if initial { cfg["tcp"] = json!(1); }
        cfg["autostart"] = json!(true);

        let backup = prompt("Second foreign Server IP/DNS (optional; Enter = single route)", "")?;
        if !backup.is_empty() {
            if !valid_peer(&backup) || backup == host {
                return Err(failure("The backup must be a different valid server IP/DNS."));
            }
            // HA becomes automatic only if a second endpoint REALLY exists;
            // neither discovery nor guessing another VPS is safe.
            cfg["ha"] = json!({
                "enabled": true,
                "listen_host": "0.0.0.0",
                "endpoints":[
                    {"name":"primary", "server":host},
                    {"name":"backup", "server":backup}
                ],
                "data_port_base":36000,
                "probe_port_base":37000,
                "probe_enabled":true,
                "probe_target":"1.1.1.1:443",
                "probe_domain":"one.one.one.one",
                "check_seconds":10,
                "failure_threshold":2,
                "success_threshold":2,
                "switch_streak":3,
                "cooldown_seconds":120,
                "max_connections":256,
                "udp_idle_seconds":90
            });
            println!("Automatic HA enabled: both remote servers must use the same key.");
        } else if initial {
            cfg.as_object_mut().unwrap().remove("ha");
            println!("Single-endpoint mode. Add a second server in the menu to enable HA.");
        }
    }

    // Never mutate the existing configuration if any input is invalid.
    store_config(&cfg)?;
    println!("Configuration saved. Applying systemd and starting automatically...");
    apply_config()?;
    println!("Ready. Open the full menu any time by typing: pingtunnel");
    Ok(())
}

pub(crate) fn protocol_menu() -> Result<()> {
    root_required()?;
    let mut cfg: Value = serde_json::from_slice(&fs::read(config_path())?)?;
    if get_string(&cfg, "type") != Some("client") {
        return Err(failure("TCP/UDP forwarding selection applies to client role."));
    }
    println!("Forwarded traffic: 1 = TCP; 0 = UDP. ICMP remains the tunnel transport.");
    let current = if cfg.get("tcp").and_then(Value::as_u64) == Some(0) { "0" } else { "1" };
    let choice = prompt("Protocol", current)?;
    if choice != "0" && choice != "1" {
        return Err(failure("Choose 0 or 1."));
    }
    cfg["tcp"] = json!(choice.parse::<u8>()?);
    store_config(&cfg)?;
    apply_config()
}

pub(crate) fn ha_disable() -> Result<()> {
    root_required()?;
    let mut cfg: Value = serde_json::from_slice(&fs::read(config_path())?)?;
    if let Some(ha) = cfg.get_mut("ha") {
        ha["enabled"] = json!(false);
    }
    store_config(&cfg)?;
    apply_config()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_generation_respects_upstream_limit() {
        for _ in 0..20 {
            let k: u64 = new_key().unwrap().parse().unwrap();
            assert!(k <= 2147483647);
        }
    }
    #[test]
    fn only_actual_destinations_are_accepted() {
        assert!(valid_destination("127.0.0.1:443"));
        assert!(!valid_destination("127.0.0.1:0"));
        assert!(!valid_destination("example.org"));
    }
}
