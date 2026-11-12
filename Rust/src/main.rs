use serde_json::{json, Value};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

mod setup;
mod menu_ui;
mod resource_monitor;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONFIG: &str = "/opt/pingtunnel/conf/config.json";
const CORE: &str = "/opt/pingtunnel/bin/pingtunnel";
const CORE_CONFIG: &str = "/run/pingtunnel-core.json";
const PERF_STATUS: &str = "/run/pingtunnel-performance.json";
const SECURITY_STATUS: &str = "/run/pingtunnel-security.json";
const UNIT: &str = "/etc/systemd/system/pingtunnel.service";
const DROPIN: &str = "/etc/systemd/system/pingtunnel.service.d/memory.conf";
const UPDATE_URL: &str =
    "https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/main/Source/install.sh";

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::Other, message.into()).into()
}

fn root_required() -> Result<()> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err(failure("Run as root (sudo pingtunnel ...)."));
    }
    Ok(())
}

fn config_path() -> PathBuf {
    PathBuf::from(CONFIG)
}

fn as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn get_string<'a>(cfg: &'a Value, field: &str) -> Option<&'a str> {
    cfg.get(field).and_then(Value::as_str)
}

fn get_number(cfg: &Value, field: &str, default: u64) -> Result<u64> {
    match cfg.get(field) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| failure(format!("{field} must be a nonnegative integer"))),
        Some(Value::String(s)) => s
            .parse::<u64>()
            .map_err(|_| failure(format!("{field} must be a nonnegative integer"))),
        Some(Value::Null) | None => Ok(default),
        _ => Err(failure(format!("{field} must be a nonnegative integer"))),
    }
}

fn validate_services_value(value:&Value)->Result<()> {
    let services=value.as_array().ok_or_else(||failure("services must be an array"))?;
    if services.is_empty() || services.len()>12 { return Err(failure("Multi-Port requires 1..12 service entries")); }
    let mut ids:Vec<String>=Vec::new(); let mut iran_ports:Vec<String>=Vec::new(); let mut foreign_ports:Vec<String>=Vec::new();
    let mut enabled=0usize; let mut tcp_enabled=false; let mut udp_enabled=false;
    for service in services {
        let id=service.get("id").and_then(Value::as_str).ok_or_else(||failure("service id is required"))?;
        let number=id.strip_prefix('S').and_then(|s|s.parse::<u8>().ok());
        if id.len()!=3 || number.is_none() || !(1..=12).contains(&number.unwrap()) || format!("S{:02}",number.unwrap())!=id {
            return Err(failure(format!("invalid service ID {id}; use S01..S12")));
        }
        if ids.iter().any(|old|old==id) {return Err(failure(format!("duplicate service ID {id}")));} ids.push(id.to_owned());
        let protocol=service.get("protocol").and_then(Value::as_str).ok_or_else(||failure(format!("{id}: protocol is required")))?;
        if protocol!="tcp" && protocol!="udp" {return Err(failure(format!("{id}: protocol must be tcp or udp")));}
        let iran=get_number(service,"iran_port",0)?; let foreign=get_number(service,"foreign_port",0)?;
        if !(1..=65535).contains(&iran) || !(1..=65535).contains(&foreign) {return Err(failure(format!("{id}: ports must be in 1..65535")));}
        let active=service.get("enabled").and_then(Value::as_bool).ok_or_else(||failure(format!("{id}: enabled must be boolean")))?;
        if !active {continue;} enabled+=1;
        if protocol=="tcp" {tcp_enabled=true;} else {udp_enabled=true;}
        let ik=format!("{protocol}:{iran}"); let fk=format!("{protocol}:{foreign}");
        if iran_ports.contains(&ik) {return Err(failure(format!("duplicate enabled Iran {protocol} port {iran}")));}
        if foreign_ports.contains(&fk) {return Err(failure(format!("duplicate enabled Foreign {protocol} port {foreign}")));}
        iran_ports.push(ik); foreign_ports.push(fk);
    }
    if enabled==0 {return Err(failure("at least one Multi-Port service must be enabled"));}
    if !tcp_enabled || !udp_enabled {return Err(failure("combined Multi-Port requires at least one enabled TCP and one enabled UDP service"));}
    Ok(())
}

fn validate(cfg: &Value) -> Result<()> {
    if !cfg.is_object()||cfg.get("schema_version").and_then(Value::as_u64)!=Some(setup::SCHEMA) {
        return Err(failure("Configuration v3 is required. Legacy settings are unsupported; back up/remove old JSON and run setup."));
    }
    let region=get_string(cfg,"region").ok_or_else(||failure("missing region"))?;
    if region!="iran"&&region!="foreign"{return Err(failure("region must be iran or foreign"));}
    let peer=get_string(cfg,"peer_ip").ok_or_else(||failure("missing peer IP"))?;
    let ip:Ipv4Addr=peer.parse().map_err(|_|failure("peer_ip must be IPv4"))?;
    if ip.is_unspecified()||ip.is_loopback()||ip.is_multicast()||ip.is_broadcast(){
        return Err(failure("peer_ip must be the opposite VPS reachable IPv4"));
    }
    let transport=get_string(cfg,"transport").ok_or_else(||failure("missing transport"))?;
    if transport!="tcp"&&transport!="udp"{return Err(failure("transport must be tcp or udp"));}
    let direction=cfg.get("icmp_direction").and_then(Value::as_str).unwrap_or("auto");
    if !matches!(direction,"auto"|"auto_direct"|"direct"|"reverse"){return Err(failure("icmp_direction must be auto, auto_direct, direct or reverse"));}
    if !(1..=65535).contains(&get_number(cfg,"port",0)?){return Err(failure("invalid local port"));}
    if let Some(services)=cfg.get("services") { validate_services_value(services)?; }
    let secret=get_string(cfg,"pair_key").ok_or_else(||failure("missing pairing key"))?;
    let bytes=STANDARD.decode(secret).map_err(|_|failure("pairing key not base64"))?;
    if bytes.len()!=32||STANDARD.encode(&bytes)!=secret{return Err(failure("pairing key must be 32 random bytes in canonical base64"));}
    if get_number(cfg,"memory_mb",0)?>1_048_576{return Err(failure("invalid memory limit"));}
    // Restrict new optional performance overrides to safe Go core ranges.
    // Experimental protocol features are opt-in; 3.3.12 defaults to the
    // proven legacy encrypted ICMP datagram format to prevent mixed-version
    // peers from silently losing UDP application traffic.
    for name in ["icmp_segment", "udp_fec"] {
        if let Some(value)=cfg.get(name) {
            if !value.is_boolean() {return Err(failure(format!("{name} must be boolean"))); }
        }
    }
    if cfg.get("udp_fec").and_then(Value::as_bool)==Some(true) &&
       cfg.get("icmp_segment").and_then(Value::as_bool)!=Some(true) {
        return Err(failure("udp_fec requires icmp_segment=true on BOTH peers"));
    }
    let udp_buffer=get_number(cfg,"udp_buf",0)?;
    if udp_buffer!=0 && !(65_536..=2_097_152).contains(&udp_buffer) {
        return Err(failure("invalid udp_buf: use 0 or 65536..=2097152 bytes"));
    }
    for (field,default,min,max) in [
        ("tcp_bs",1_048_576,65_536,2_097_152),
        ("tcp_mw",20_000,256,20_000),
        ("tcp_rst",400,300,2_400),
        ("timeout",60,30,120),
    ] {
        if !(min..=max).contains(&get_number(cfg,field,default)?) {
            return Err(failure(format!("invalid {field}: expected {min}..={max}")));
        }
    }
    if cfg.get("autostart").and_then(Value::as_bool).is_none(){return Err(failure("autostart must be boolean"));}
    Ok(())
}

fn load_config() -> Result<Value> {
    let bytes = fs::read(config_path()).map_err(|e| {
        failure(format!("Cannot read {CONFIG}: {e}. Run sudo pingtunnel configure."))
    })?;
    let value: Value = serde_json::from_slice(&bytes)?;
    validate(&value)?;
    Ok(value)
}

fn atomic_save(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("pending-{}", process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)?;
    let saved = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    })();
    if saved.is_err() {
        let _ = fs::remove_file(&temp);
    }
    saved
}

fn store_config(cfg: &Value) -> Result<()> {
    validate(cfg)?;
    let mut json = serde_json::to_vec_pretty(cfg)?;
    json.push(b'\n');
    atomic_save(&config_path(), &json, 0o600)
}

// The integer Pingtunnel identifier is derived from the root secret, never
// entered by a user or reused as the actual 256-bit encryption key.
fn numeric_auth_code(pair_key:&str)->Result<u32>{
    let bytes=STANDARD.decode(pair_key)?;
    if bytes.len()!=32{return Err(failure("invalid root key"));}
    let mut digest=Sha256::new();
    digest.update(b"pingtunnel-v3/packet-id");
    digest.update(&bytes);
    let hash=digest.finalize();
    Ok((u32::from_be_bytes([hash[0],hash[1],hash[2],hash[3]]) & 0x7fff_ffff).max(1))
}

fn service_alias(id:&str)->String { format!("msm-service:{id}") }

fn go_core_config(cfg:&Value)->Result<Value>{
    validate(cfg)?;
    let region=get_string(cfg,"region").unwrap();
    let peer=get_string(cfg,"peer_ip").unwrap();
    let key=get_string(cfg,"pair_key").unwrap();
    let transport=get_string(cfg,"transport").unwrap();
    let port=get_number(cfg,"port",0)?;
    let protocol=if transport=="tcp"{1}else{0};
    let mut config=json!({
        "type":if region=="iran"{"client"}else{"server"},
        "key":numeric_auth_code(key)?,
        "encrypt":"auto", "encrypt_key":key, "region":region,
        "tcp":protocol,"noprint":0,"nolog":1,"loglevel":"error",
        "icmp_direction":cfg.get("icmp_direction").and_then(Value::as_str).unwrap_or("auto")
    });
    // Never opt in a node automatically: an older peer may not understand
    // the protected fragment extension even if the main wire version is 4.
    config["icmp_segment"]=json!(cfg.get("icmp_segment").and_then(Value::as_bool).unwrap_or(false));
    config["udp_fec"]=json!(cfg.get("udp_fec").and_then(Value::as_bool).unwrap_or(false));
    if let Some(services)=cfg.get("services").and_then(Value::as_array) {
        let first=services.iter().find(|service|service.get("enabled").and_then(Value::as_bool)==Some(true))
            .ok_or_else(||failure("Multi-Port has no enabled services"))?;
        let id=get_string(first,"id").ok_or_else(||failure("Multi-Port service ID missing"))?;
        let iran_port=get_number(first,"iran_port",0)?; let foreign_port=get_number(first,"foreign_port",0)?;
        config["services"]=json!(services);
        if region=="iran" {
            config["timeout"]=json!(get_number(cfg,"timeout",60)?);
            config["tcp_bs"]=json!(get_number(cfg,"tcp_bs",1_048_576)?);
            config["tcp_mw"]=json!(get_number(cfg,"tcp_mw",20_000)?);
            config["tcp_rst"]=json!(get_number(cfg,"tcp_rst",400)?);
            let buf=get_number(cfg,"udp_buf",0)?; if buf>0 {config["udp_buf"]=json!(buf);}
            config["listen"]=json!(format!(":{iran_port}"));
            config["server"]=json!(peer);
            config["target"]=json!(service_alias(id));
        } else {
            config["peer_ip"]=json!(peer);
            config["fixed_target"]=json!(format!("127.0.0.1:{foreign_port}"));
            config["forward_protocol"]=json!(protocol);
        }
        return Ok(config);
    }
    if region=="iran"{
        config["timeout"]=json!(get_number(cfg,"timeout",60)?);
        // The client owns TCP framing; the foreign service gets these values
        // over authenticated packets and never needs divergent local tuning.
        if transport=="tcp" {
            config["tcp_bs"]=json!(get_number(cfg,"tcp_bs",1_048_576)?);
            config["tcp_mw"]=json!(get_number(cfg,"tcp_mw",20_000)?);
            config["tcp_rst"]=json!(get_number(cfg,"tcp_rst",400)?);
        } else {
            let buf=get_number(cfg,"udp_buf",0)?;
            if buf>0 {config["udp_buf"]=json!(buf);}
        }
        config["listen"]=json!(format!(":{port}"));
        config["server"]=json!(peer);
        // The foreign server MUST ignore this compatibility placeholder.
        config["target"]=json!("127.0.0.1:1");
    }else{
        config["peer_ip"]=json!(peer);
        config["fixed_target"]=json!(format!("127.0.0.1:{port}"));
        config["forward_protocol"]=json!(protocol);
    }
    Ok(config)
}

fn run_core(dry_run: bool) -> Result<()> {
    let cfg = load_config()?;
    let bin = PathBuf::from(CORE);
    if !bin.is_file() {
        return Err(failure(format!("Missing Go core at {}", bin.display())));
    }
    let go = go_core_config(&cfg)?;
    if dry_run {
        println!("{} -c {}  (key material stored in private 0600 JSON, not command line)",
            bin.display(), CORE_CONFIG);
        println!("Cipher: {}", if go.get("encrypt") == Some(&json!("auto")) {
            "AUTO (CPU benchmark AES-256-GCM / XChaCha20-Poly1305)"
        } else { "legacy unencrypted (run Easy setup on BOTH servers)" });
        return Ok(());
    }
    let serialized = serde_json::to_vec(&go)?;
    atomic_save(Path::new(CORE_CONFIG), &serialized, 0o600)?;
    let error = Command::new(&bin).arg("-c").arg(CORE_CONFIG).exec();
    Err(Box::new(error))
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl").args(args).status()?;
    if !status.success() {
        return Err(failure(format!("systemctl {} failed: {status}", args.join(" "))));
    }
    Ok(())
}

fn prompt(title: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("{title}: ");
    } else {
        print!("{title} [{default}]: ");
    }
    io::stdout().flush()?;
    let mut line = String::new();
    let count = io::stdin().read_line(&mut line)?;
    if count == 0 {
        return Err(failure("Input closed."));
    }
    let answer = line.trim();
    Ok(if answer.is_empty() { default.to_owned() } else { answer.to_owned() })
}

fn service_install() -> Result<()> {
    root_required()?;
    let cfg = load_config()?;
    if !Path::new("/run/systemd/system").exists() {
        return Err(failure("systemd is not running on this host."));
    }
    let service = r#"[Unit]
Description=Pingtunnel ICMP tunnel (Rust-managed, Go core)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/pingtunnel run
WorkingDirectory=/opt/pingtunnel
Restart=always
RestartSec=5
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pingtunnel

[Install]
WantedBy=multi-user.target
"#;
    // One direct ICMP route only; systemd supervises the Go core.
    atomic_save(Path::new(UNIT), service.as_bytes(), 0o644)?;
    let memory = get_number(&cfg, "memory_mb", 0)?;
    if memory > 0 {
        let contents = format!("[Service]\nMemoryMax={memory}M\n");
        atomic_save(Path::new(DROPIN), contents.as_bytes(), 0o644)?;
    } else if Path::new(DROPIN).exists() {
        fs::remove_file(DROPIN)?; // removes the legacy MemoryLimit drop-in too
    }
    run_systemctl(&["daemon-reload"])?;
    if cfg.get("autostart").and_then(Value::as_bool).unwrap_or(false) {
        run_systemctl(&["enable", "pingtunnel.service"])?;
    } else {
        // Preserve explicit start/stop choice. Do not auto-start a disabled service.
        run_systemctl(&["disable", "pingtunnel.service"])?;
    }
    println!("Single-route Go service installed; no resident Rust manager.");
    Ok(())
}

// All changes entered in a menu are applied immediately: systemd unit,
// autostart and the active Go core are kept in sync with the saved settings.
fn apply_config() -> Result<()> {
    service_install()?;
    run_systemctl(&["restart", "pingtunnel.service"])?;
    Ok(())
}

fn update() -> Result<()> {
    root_required()?;
    // mktemp creates a unique, root-owned file (avoids predictable /tmp names).
    let created = Command::new("mktemp").output()?;
    if !created.status.success() {
        return Err(failure("mktemp failed."));
    }
    let temp = PathBuf::from(String::from_utf8(created.stdout)?.trim());
    let status = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error", "--retry", "3", UPDATE_URL, "-o"])
        .arg(&temp)
        .status()?;
    if !status.success() {
        let _ = fs::remove_file(&temp);
        return Err(failure("Failed to download update installer."));
    }
    let result = Command::new("bash").arg(&temp).status();
    let _ = fs::remove_file(&temp);
    if !result?.success() {
        return Err(failure("Update installer failed."));
    }
    Ok(())
}

// A missing path is normal for partially uninstalled or interrupted installs.
fn remove_known_file(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(failure(format!("Cannot remove {path}: {e}"))),
    }
}

fn remove_known_dir(path: &str) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(failure(format!("Cannot remove directory {path}: {e}"))),
    }
}

fn uninstall(purge: bool) -> Result<()> {
    root_required()?;
    if purge {
        println!("PERMANENT PURGE: removes pairing keys, configuration and all Pingtunnel data.");
        if prompt("Type PURGE to confirm", "")? != "PURGE" {
            println!("Cancelled. No changes made.");
            return Ok(());
        }
    } else {
        println!("Uninstall binaries and service; keep pairing configuration and private keys.");
        if prompt("Type YES to confirm", "")? != "YES" {
            println!("Cancelled. No changes made.");
            return Ok(());
        }
    }
    // A partially uninstalled host may have no unit. Stop is best-effort,
    // but never delete the executable while the unit is still active.
    let _ = run_systemctl(&["stop", "pingtunnel.service"]);
    if Command::new("systemctl")
        .args(["is-active", "--quiet", "pingtunnel.service"])
        .status().is_ok_and(|status| status.success()) {
        return Err(failure("Service is still active; refusing to remove a running tunnel."));
    }
    let _ = run_systemctl(&["disable", "pingtunnel.service"]);

    remove_known_file(UNIT)?;
    // systemctl disable can fail after a partial uninstall has removed the unit.
    remove_known_file("/etc/systemd/system/multi-user.target.wants/pingtunnel.service")?;
    // Remove every Pingtunnel-specific drop-in, not merely memory.conf.
    remove_known_dir("/etc/systemd/system/pingtunnel.service.d")?;
    run_systemctl(&["daemon-reload"])?;
    let _ = run_systemctl(&["reset-failed", "pingtunnel.service"]);

    // Run-time files are not configuration and must not survive uninstall.
    for path in [
        CORE_CONFIG,
        PERF_STATUS,
        SECURITY_STATUS,
        "/run/pingtunnel.pid",
        "/usr/local/bin/install_pingtunnel.py",
        "/opt/pingtunnel/run_pingtunnel.py",
    ] {
        remove_known_file(path)?;
    }
    remove_known_dir("/opt/pingtunnel/bin")?;
    if purge {
        remove_known_dir("/opt/pingtunnel")?;
        remove_known_dir("/var/log/pingtunnel")?;
    }
    // Remove the manager last so a partial failure remains repairable.
    remove_known_file("/usr/local/bin/pingtunnel")?;
    if purge {
        println!("Pingtunnel purged: service, binaries, runtime files and private config removed.");
    } else {
        println!("Pingtunnel uninstalled. Pairing config kept in /opt/pingtunnel/conf/config.json.");
        println!("Use: pingtunnel uninstall --purge (before uninstall) for permanent config removal.");
    }
    Ok(())
}

fn help(){
    println!("Pingtunnel Manager v{} — pairing v3",env!("CARGO_PKG_VERSION"));
    println!("  pingtunnel            Unified menu");
    println!("  pingtunnel setup      Five questions on each VPS");
    println!("  pingtunnel key        Show existing pairing key (root only)");
    println!("  pingtunnel validate | performance | security | health [--peer] | dry-run");
    println!("  pingtunnel start | stop | restart | status | logs [lines]");
    println!("  pingtunnel route show | auto-reverse | auto-direct | manual-reverse | manual-direct");
    println!("  pingtunnel services list|add|edit|remove|enable|disable|check|export|import");
    println!("  pingtunnel update | uninstall [--purge]  (permanent purge requires PURGE confirmation)");
}

fn display_pair_key()->Result<()>{
    root_required()?;
    let config=load_config()?;
    println!("Secret pairing key: {}",get_string(&config,"pair_key").unwrap());
    println!("Keep it private and use it only to pair the opposite VPS.");
    Ok(())
}

fn current_service_state() -> String {
    // Status reporting must not require a functional tunnel or leak secrets.
    match Command::new("systemctl")
        .args(["is-active", "pingtunnel.service"])
        .output()
    {
        Ok(result) => {
            let state=String::from_utf8_lossy(&result.stdout);
            match state.trim() {
                "active" => "active".into(),
                "inactive" => "inactive".into(),
                "activating" => "activating".into(),
                "deactivating" => "deactivating".into(),
                "failed" => "failed".into(),
                _ => "unavailable".into(),
            }
        }
        Err(_) => "unavailable".into(),
    }
}

fn route_policy_label(direction:&str)->&'static str {
    match direction {
        "auto" => "AUTO Reverse first",
        "auto_direct" => "AUTO Direct first",
        "reverse" => "MANUAL Reverse only",
        "direct" => "MANUAL Direct only",
        _ => "Unconfigured"
    }
}

// Changes are local to this VPS, require root and restart the Go core.
// Use the same option on BOTH peers in a coordinated maintenance window.
fn route_policy_set(choice:&str)->Result<()> {
    root_required()?;
    let mode=match choice {
        "auto-reverse" => "auto",
        "auto-direct" => "auto_direct",
        "manual-reverse" => "reverse",
        "manual-direct" => "direct",
        _=>return Err(failure("Route options: auto-reverse | auto-direct | manual-reverse | manual-direct | show"))
    };
    let previous=load_config()?;
    let old=previous.get("icmp_direction").and_then(Value::as_str).unwrap_or("auto");
    if old==mode {
        println!("Unchanged: {}",route_policy_label(mode));
        return Ok(());
    }
    let mut next=previous.clone();
    next["icmp_direction"]=json!(mode);
    validate(&next)?;
    // Store atomically, then apply; restore previous config if the service
    // restart fails so future daemon restarts don't use a half-applied mode.
    store_config(&next)?;
    if let Err(err)=apply_config() {
        let _=store_config(&previous);
        let _=apply_config();
        return Err(failure(format!("Route policy apply failed (prior config restored): {err}")));
    }
    println!("Route policy activated: {}",route_policy_label(mode));
    println!("IMPORTANT: Select the SAME policy on the opposite VPS.");
    Ok(())
}

fn route_policy_menu()->Result<()> {
    root_required()?;
    let cfg=load_config()?;
    let current=cfg.get("icmp_direction").and_then(Value::as_str).unwrap_or("auto");
    println!("\nICMP Route Policy — current: {}",route_policy_label(current));
    println!("  1) AUTO — Reverse first; Direct if Reverse fails; restore Reverse");
    println!("  2) AUTO — Direct first; Reverse if Direct fails; restore Direct");
    println!("  3) MANUAL — locked to a chosen direction, NO automatic switching");
    println!("  0) Cancel");
    println!("WARNING: update BOTH VPS peers to matching policies.");
    let selected=prompt("Select policy","0")?;
    let choice=match selected.as_str() {
        "1"=>"auto-reverse",
        "2"=>"auto-direct",
        "3"=>{
            println!("  1) Reverse only     2) Direct only     0) Cancel");
            match prompt("Manual route","0")?.as_str() {
                "1"=>"manual-reverse",
                "2"=>"manual-direct",
                "0"=>return Ok(()),
                _=>return Err(failure("Choose 1 or 2 for manual direction.")),
            }
        },
        "0"=>return Ok(()),
        _=>return Err(failure("Choose 1, 2, 3 or 0.")),
    };
    route_policy_set(choice)
}

fn legacy_service_rows(cfg:&Value)->Vec<Value> {
    let protocol=get_string(cfg,"transport").unwrap_or("tcp"); let port=get_number(cfg,"port",443).unwrap_or(443);
    let mut rows=vec![json!({"id":"S01","protocol":"tcp","iran_port":443,"foreign_port":443,"enabled":false}),
        json!({"id":"S02","protocol":"udp","iran_port":444,"foreign_port":444,"enabled":false})];
    if protocol=="udp" {rows[1]["iran_port"]=json!(port);rows[1]["foreign_port"]=json!(port);rows[1]["enabled"]=json!(true);rows[0]["enabled"]=json!(true);}
    else {rows[0]["iran_port"]=json!(port);rows[0]["foreign_port"]=json!(port);rows[0]["enabled"]=json!(true);rows[1]["enabled"]=json!(true);}
    rows
}
fn current_service_rows(cfg:&Value)->Vec<Value> {cfg.get("services").and_then(Value::as_array).cloned().unwrap_or_else(||legacy_service_rows(cfg))}
fn next_service_id(services:&[Value])->Result<String> {
    for n in 1..=12 {let id=format!("S{n:02}");if !services.iter().any(|s|s.get("id").and_then(Value::as_str)==Some(id.as_str())){return Ok(id);}}
    Err(failure("Multi-Port is limited to 12 service IDs (S01..S12)"))
}
fn print_services(services:&[Value]) {
    println!("{:<5} {:<5} {:>12} {:>14} {:>9}","ID","Proto","Iran Listen","Foreign Target","State");println!("{}", "-".repeat(52));
    for service in services {println!("{:<5} {:<5} {:>12} {:>14} {:>9}",
        service["id"].as_str().unwrap_or("?"),service["protocol"].as_str().unwrap_or("?").to_uppercase(),
        service["iran_port"].as_u64().unwrap_or(0),service["foreign_port"].as_u64().unwrap_or(0),
        if service["enabled"].as_bool()==Some(true){"enabled"}else{"disabled"});}
}
fn apply_services_update(previous:Value,services:Vec<Value>)->Result<()> {
    let mut next=previous.clone(); next["services"]=json!(services);
    let first=services.iter().find(|s|s.get("enabled").and_then(Value::as_bool)==Some(true)).ok_or_else(||failure("at least one service must remain enabled"))?;
    let local_port=if get_string(&next,"region")==Some("iran"){get_number(first,"iran_port",0)?}else{get_number(first,"foreign_port",0)?};
    next["port"]=json!(local_port);
    // Keep the pre-existing transport selector as the queue-policy profile.
    // Queue sizes, TCP tuning, timeouts and adaptive settings are not rewritten.
    validate(&next)?; store_config(&next)?;
    if let Err(err)=apply_config(){let _=store_config(&previous);let _=apply_config();return Err(failure(format!("Multi-Port change failed; previous config restored: {err}")));}
    println!("Multi-Port configuration applied. Existing queue/performance settings were retained.");Ok(())
}
fn services_cli(args:&[String])->Result<()> {
    root_required()?; if args.is_empty(){return services_menu();}
    let action=args[0].as_str();let previous=load_config()?;let mut services=current_service_rows(&previous);
    match action {
        "list"|"status"=>{print_services(&services);Ok(())}
        "check"=>{let mut candidate=previous.clone();candidate["services"]=json!(services);validate(&candidate)?;
            println!("Multi-Port profile valid: {} slots, {} enabled.",services.len(),services.iter().filter(|s|s["enabled"].as_bool()==Some(true)).count());Ok(())}
        "export"=>{let path=if let Some(v)=args.get(1){v.clone()}else{prompt("Export path","/root/pingtunnel-services.json")?};
            let mut bytes=serde_json::to_vec_pretty(&json!({"profile_version":1,"services":services}))?;bytes.push(b'\n');
            atomic_save(Path::new(&path),&bytes,0o600)?;println!("Service-only profile exported to {path}. Pairing keys are not included.");Ok(())}
        "import"=>{let path=if let Some(v)=args.get(1){v.clone()}else{prompt("Profile file","/root/pingtunnel-services.json")?};
            let profile:Value=serde_json::from_slice(&fs::read(&path)?)?;
            let imported=profile.get("services").and_then(Value::as_array).ok_or_else(||failure("profile must contain a services array"))?.clone();
            apply_services_update(previous,imported)}
        "add"=>{if services.len()>=12{return Err(failure("Multi-Port is limited to 12 service slots"));}
            let protocol_raw=if let Some(v)=args.get(1){v.clone()}else{prompt("Protocol (tcp/udp)","tcp")?};
            let protocol=protocol_raw.to_ascii_lowercase();
            let iran=if let Some(v)=args.get(2){v.clone()}else{prompt("Iran ingress port","443")?};
            let foreign=if let Some(v)=args.get(3){v.clone()}else{prompt("Foreign loopback target port","443")?};
            let iran_port:u16=iran.parse().map_err(|_|failure("Iran port must be 1..65535"))?;
            let foreign_port:u16=foreign.parse().map_err(|_|failure("Foreign port must be 1..65535"))?;
            let id=next_service_id(&services)?;services.push(json!({"id":id,"protocol":protocol,"iran_port":iran_port,"foreign_port":foreign_port,"enabled":true}));
            apply_services_update(previous,services)}
        "edit"=>{let id=if let Some(v)=args.get(1){v.clone()}else{prompt("Service ID","S01")?};
            let index=services.iter().position(|s|s["id"].as_str()==Some(id.as_str())).ok_or_else(||failure(format!("service {id} not found")))?;
            let protocol=prompt("Protocol (tcp/udp)",services[index]["protocol"].as_str().unwrap_or("tcp"))?.to_ascii_lowercase();
            let iran=prompt("Iran ingress port",&services[index]["iran_port"].as_u64().unwrap_or(443).to_string())?;
            let foreign=prompt("Foreign loopback target port",&services[index]["foreign_port"].as_u64().unwrap_or(443).to_string())?;
            let iran_port:u16=iran.parse().map_err(|_|failure("Iran port must be 1..65535"))?;let foreign_port:u16=foreign.parse().map_err(|_|failure("Foreign port must be 1..65535"))?;
            services[index]["protocol"]=json!(protocol);services[index]["iran_port"]=json!(iran_port);services[index]["foreign_port"]=json!(foreign_port);
            apply_services_update(previous,services)}
        "remove"=>{let id=if let Some(v)=args.get(1){v.clone()}else{prompt("Service ID","S12")?};let before=services.len();services.retain(|s|s["id"].as_str()!=Some(id.as_str()));
            if services.len()==before{return Err(failure(format!("service {id} not found")));}apply_services_update(previous,services)}
        "enable"|"disable"=>{let id=if let Some(v)=args.get(1){v.clone()}else{prompt("Service ID","S01")?};
            let service=services.iter_mut().find(|s|s["id"].as_str()==Some(id.as_str())).ok_or_else(||failure(format!("service {id} not found")))?;
            service["enabled"]=json!(action=="enable");apply_services_update(previous,services)}
        _=>Err(failure("Usage: pingtunnel services [list|add|edit ID|remove ID|enable ID|disable ID|check|export [PATH]|import PATH]"))
    }
}
fn services_menu()->Result<()> {
    root_required()?;
    loop {println!("\nMulti-Port Services — TCP + UDP (maximum 12)");
        println!("  1) View services");println!("  2) Add service");println!("  3) Edit service");println!("  4) Remove service");
        println!("  5) Enable service");println!("  6) Disable service");println!("  7) Export service profile");println!("  8) Import service profile");
        println!("  9) Validate profile");println!("  0) Back");
        match prompt("Select","0")?.as_str() {
            "1"=>services_cli(&["list".into()])?,"2"=>services_cli(&["add".into()])?,"3"=>services_cli(&["edit".into()])?,
            "4"=>services_cli(&["remove".into()])?,"5"=>services_cli(&["enable".into()])?,"6"=>services_cli(&["disable".into()])?,
            "7"=>services_cli(&["export".into()])?,"8"=>services_cli(&["import".into()])?,"9"=>services_cli(&["check".into()])?,
            "0"=>return Ok(()),_=>println!("Choose 0..9."),
        }
    }
}

fn menu()->Result<()>{
    root_required()?;
    // Samples exist only while this CLI is displaying the dashboard.
    let mut monitor=resource_monitor::ResourceMonitor::new();
    monitor.refresh();
    loop{
        let cfg=load_config().ok();
        let default=if cfg.is_some(){"1"}else{"6"};
        let display=|resources:resource_monitor::Resources, columns:u16, rows:u16| -> String {
            let state=current_service_state();
            let view=menu_ui::MenuView{
                version:env!("CARGO_PKG_VERSION"),
                region:cfg.as_ref().and_then(|v|get_string(v,"region")).unwrap_or("unknown"),
                peer:cfg.as_ref().and_then(|v|get_string(v,"peer_ip")).unwrap_or("-"),
                transport:cfg.as_ref().map(|v|if v.get("services").and_then(Value::as_array).is_some(){"TCP+UDP"}else{get_string(v,"transport").unwrap_or("-")}).unwrap_or("-"),
                route:cfg.as_ref().and_then(|v|get_string(v,"icmp_direction")).unwrap_or("auto"),
                port:cfg.as_ref().and_then(|v|if let Some(services)=v.get("services").and_then(Value::as_array){Some(services.len() as u64)}else{v.get("port").and_then(Value::as_u64)})
                    .and_then(|n|u16::try_from(n).ok()),
                service:&state,
                configured:cfg.is_some(),
                resources,
            };
            menu_ui::render_sized(&view,menu_ui::supports_color(),menu_ui::supports_unicode(),columns,rows)
        };
        let choice=if menu_ui::interactive_available(){
            // Alternate screen + raw keyboard mode are restored BEFORE each action.
            menu_ui::choose(&mut monitor,display,default)?
        }else{
            print!("{}",display(monitor.current(),80,40));
            prompt("Choose (1-16)",default)?
        };
        let action=match choice.as_str(){
            "1"=>run_systemctl(&["status","pingtunnel.service","--no-pager"]),
            "2"=>run_systemctl(&["start","pingtunnel.service"]),
            "3"=>run_systemctl(&["stop","pingtunnel.service"]),
            "4"=>run_systemctl(&["restart","pingtunnel.service"]),
            "5"=>logs("100"),
            "6"=>setup::wizard(),
            "7"=>display_pair_key(),
            "8"=>show_adaptive_status(),
            "9"=>{load_config()?;println!("Version-3 config valid");Ok(())},
            "10"=>update(),
            "11"=>uninstall(false),
            "12"|"q"|"Q"=>return Ok(()),
            "13"=>show_security_status(),
            "14"=>show_health(false),
            "15"=>route_policy_menu(),
            "16"=>services_menu(),
            _=>{println!("Invalid choice: use 1..16.");continue}
        };
        if choice=="11" && action.is_ok() && !Path::new("/usr/local/bin/pingtunnel").exists() {
            return Ok(());
        }
        if let Err(e)=action{eprintln!("Operation failed: {e}");}
        // Hold command output until confirmed; otherwise the alternate-screen
        // menu instantly erases status, logs and diagnostics.
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            println!("\nPress Enter to return to the menu...");
            io::stdout().flush()?;
            let mut ignored = String::new();
            if io::stdin().read_line(&mut ignored)? == 0 {return Ok(());}
        }
        monitor.refresh();
    }
}

// Do not equate a running service with an authenticated usable peer.
// The optional strict mode only proves recent authenticated peer traffic;
// it does NOT replace an application-level UDP/TCP round-trip test.
fn recent_authenticated_peer(status: &Value, max_age_seconds: i64) -> bool {
    status["state"].as_str() == Some("authenticated")
        && status["last_valid_age_seconds"].as_i64()
            .is_some_and(|age| age >= 0 && age <= max_age_seconds)
}

fn show_health(require_peer: bool) -> Result<()> {
    // Verify process liveness separately from ICMP path quality.
    let service = Command::new("systemctl").args(["is-active","--quiet","pingtunnel.service"]).status()?;
    if !service.success() {
        return Err(failure("Pingtunnel systemd service is not active; inspect sudo pingtunnel logs 100."));
    }
    let meta=fs::metadata(SECURITY_STATUS)
        .map_err(|_|failure("Service is active but the Go security heartbeat is missing"))?;
    let age=meta.modified()?.elapsed()?.as_secs();
    if age>10 {
        return Err(failure(format!("Go security heartbeat stale by {age} seconds; core workers may have failed")));
    }
    let status:Value=serde_json::from_slice(&fs::read(SECURITY_STATUS)?)?;
    if status["wire_version"].as_i64()!=Some(4) || status["config_schema"].as_i64()!=Some(3) {
        return Err(failure("Go runtime status is incompatible with config schema 3 / wire 4"));
    }
    println!("Service active and Go workers reporting (heartbeat {}s ago).",age);
    println!("Process health is not proof of end-to-end application connectivity.");
    println!("Security session state: {}",status["state"].as_str().unwrap_or("unknown"));
    if let Some(direction)=status["icmp_direction"].as_str(){println!("ICMP initiation: {direction}");}
    if let Some(reason)=status["auto_direct_fallback_reason"].as_str(){
        println!("Last emergency direct fallback: {reason}");
    }
    if let Some(age)=status["reverse_probe_age_seconds"].as_i64().filter(|a|*a>=0) {
        println!("Last authenticated inbound reverse poll: {age}s ago (one-way evidence).");
    }
    println!("Last authenticated peer traffic: {} seconds ago.",status["last_valid_age_seconds"]);
    if status["region"].as_str()==Some("iran") {
        let age=status["last_valid_age_seconds"].as_i64().unwrap_or(-1);
        if status["state"].as_str()!=Some("authenticated") {
            println!("WARNING: opposite VPS has not completed the authenticated ICMP handshake.");
        } else if age<0 || age>35 {
            println!("WARNING: no recent authenticated ICMP response; service active does NOT mean tunnel online.");
        }
    }
    if require_peer && !recent_authenticated_peer(&status, 35) {
        return Err(failure("No authenticated peer traffic in the past 35 seconds; process may be alive but peer reachability is unverified."));
    }
    Ok(())
}

fn show_security_status() -> Result<()> {
    let metadata = match fs::metadata(SECURITY_STATUS) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            println!("Security status unavailable: Go core has not published a session report.");
            return Ok(());
        }
        Err(err) => return Err(Box::new(err)),
    };
    if let Ok(age) = metadata.modified()?.elapsed() {
        if age.as_secs()>15 {
            println!("WARNING: security status is stale ({} seconds old). Check systemd.",age.as_secs());
        }
    }
    let report: Value=serde_json::from_slice(&fs::read(SECURITY_STATUS)?)?;
    println!("Authenticated session: {}",report["state"].as_str().unwrap_or("unknown"));
    println!("  Config schema: {} | Wire version: {}",report["config_schema"],report["wire_version"]);
    println!("  Region: {}",report["region"].as_str().unwrap_or("unknown"));
    if let Some(direction)=report["icmp_direction"].as_str(){println!("  ICMP initiation: {direction}");}
    if report["auto_route_policy"].as_str()==Some("direct_preferred_reverse_on_failure") {
        println!("  AUTO policy: Direct preferred, Reverse only on signed demand + confirmed Direct failure");
        println!("  Verified returns to preferred Direct: {}",report["auto_preferred_reverse_returns"]);
    } else if report["auto_route_policy"].as_str()==Some("manual_direct") {
        println!("  MANUAL policy: Direct only (automatic switching disabled)");
    } else if report["auto_route_policy"].as_str()==Some("manual_reverse") {
        println!("  MANUAL policy: Reverse only (automatic switching disabled)");
    } else if report["auto_route_policy"].as_str()==Some("reverse_preferred_direct_on_failure") {
        println!("  AUTO policy: Reverse preferred, Direct only on confirmed failure");
        if report["icmp_direction"].as_str()==Some("direct") {
            println!("  Reverse health check: every 10s; 2 signed return-path proofs required");
            println!("  Reverse proofs: {} / 2 | last proof age: {} ms | takeover pending: {}",
                report["auto_reverse_proof_confirmations"].as_u64().unwrap_or(0),
                report["auto_reverse_last_proof_age_ms"],
                report["auto_pending_reverse_handoff"].as_bool().unwrap_or(false));
        }
        println!("  Verified returns to preferred Reverse: {}",
            report["auto_preferred_reverse_returns"].as_u64().unwrap_or(0));
    }
    if let Some(count)=report["auto_direct_fallback_count"].as_u64().filter(|value|*value>0){
        println!("  Emergency Reverse→Direct failovers: {count}");
        if let Some(reason)=report["auto_direct_fallback_reason"].as_str(){
            println!("  Last failover reason: {reason}");
        }
    }
    if let Some(age)=report["reverse_probe_age_seconds"].as_i64().filter(|a|*a>=0) {
        println!("  Inbound reverse probe age: {age}s (does not confirm return path)");
    }
    println!("  Last valid message age: {} seconds",report["last_valid_age_seconds"]);
    println!("  Pending key renegotiation: {}",report["pending_rekey"]);
    println!("  Replays rejected: {}",report["replay_drops"]);
    println!("  Authentication failures: {}",report["authentication_failures"]);
    if let Some(failed)=report["icmp_write_failures"].as_u64() {
        println!("  ICMP socket write failures (all paths): {failed}");
    }
    if let Some(oversize)=report["icmp_write_emsgsize"].as_u64() {
        println!("  ICMP EMSGSIZE / message-too-long errors: {oversize}");
    }
    if let Some(oversize)=report["reverse_oversized_drops"].as_u64() {
        println!("  Reverse encrypted frames rejected (>10,240 bytes): {oversize}");
    }
    if let Some(drops)=report["udp_dispatch_overflow_drops"].as_u64() {
        println!("  UDP/QUIC ingress dispatch queue drops (cumulative): {drops}");
        if drops>0 {
            println!("  NOTE: UDP dispatcher intentionally drops under saturation to avoid blocking the ICMP reader.");
        }
    }
    if let Some(truncated)=report["udp_truncated_datagrams"].as_u64() {
        println!("  UDP receive-buffer truncation events (cumulative): {truncated}");
    }
    if let (Some(req),Some(rep),Some(pps),Some(peak))=(
        report["icmp_userspace_echo_requests"].as_u64(),
        report["icmp_userspace_echo_replies"].as_u64(),
        report["icmp_userspace_pps"].as_u64(),
        report["icmp_userspace_peak_pps"].as_u64()) {
        println!("  ICMP userspace Echo Requests / Replies: {req} / {rep}");
        println!("  ICMP userspace send rate / peak: {pps} / {peak} packets/s (excludes kernel echoes)");
    }
    if let (Some(proofs),Some(attempts))=(
        report["reverse_path_proofs"].as_u64(),
        report["reverse_return_attempts"].as_u64()) {
        println!("  Confirmed Reverse return-path proofs / switch attempts: {proofs} / {attempts}");
    }
    if let (Some(polls),Some(saved))=(
        report["reverse_polls_sent"].as_u64(),
        report["reverse_polls_coalesced"].as_u64()) {
        println!("  Signed Reverse polls sent / coalesced into DATA opportunities: {polls} / {saved}");
    }
    if let Some(count)=report["reverse_queue_hints_received"].as_u64().filter(|c|*c>0) {
        println!("  Authenticated remote queue hints: received {count}, rejected {}",
            report["reverse_queue_hints_rejected"]);
        let age=report["reverse_remote_queue_hint_age_ms"].as_i64().unwrap_or(-1);
        if age<0 || age>1200 {
            println!("  Remote queue: no FRESH report; last hint was {age}ms ago (not live queue pressure)");
        } else {
            println!("  Last remote queue: {} packets / {} bytes / oldest {}ms | hint age {}ms",
                report["reverse_remote_queue_hint_depth"],
                report["reverse_remote_queue_hint_bytes"],
                report["reverse_remote_queue_hint_oldest_ms"],
                report["reverse_remote_queue_hint_age_ms"]);
        }
        println!("  Queue-aware adaptive poll interval: {}ms (minimum 8ms, including write-error backoff)",
            report["reverse_poll_interval_ms"]);
    }
    if let Some(backoff)=report["reverse_poll_backoff_remaining_ms"].as_i64().filter(|v|*v>0) {
        println!("  Local ICMP write failures: poll pressure reduced for {backoff}ms");
    }
    if let (Some(sent),Some(received),Some(limited))=(
        report["reverse_backlog_wakes_sent"].as_u64(),
        report["reverse_backlog_wakes_accepted"].as_u64(),
        report["reverse_backlog_wakes_rate_limited"].as_u64()) {
        println!("  Encrypted backlog wakeup hints sent / verified / rate-limited: {sent} / {received} / {limited}");
        if let Some(remaining)=report["reverse_wake_burst_remaining_ms"].as_i64().filter(|v|*v>0) {
            println!("  Data-driven Reverse fast-poll burst remaining: {remaining} ms");
        }
    }
    if let (Some(checks),Some(proofs))=(
        report["direct_probe_checks"].as_u64(),
        report["direct_path_proofs"].as_u64()) {
        println!("  Background Direct checks / authenticated replies: {checks} / {proofs} (while Reverse is active)");
        if let Some(age)=report["direct_last_proof_age_seconds"].as_i64().filter(|age|*age>=0){
            println!("  Last confirmed Direct test reply: {age}s ago");
        }
    }
    // Legacy versions expose a nonzero Smart Rotation interval. v3.3.20
    // explicitly disables healthy Reverse->Direct timer switches.
    if let Some(seconds)=report["smart_rotation_interval_seconds"].as_u64().filter(|s|*s>0) {
        println!("  Smart Rotation: ACTIVE | schedule every {} hours, only if both paths are authenticated/healthy",seconds/3600);
        println!("  Rotation due: {} | completed: {} | retry windows: {}",
            report["smart_rotation_due"].as_bool().unwrap_or(false),
            report["smart_rotation_count"].as_u64().unwrap_or(0),
            report["smart_rotation_retries"].as_u64().unwrap_or(0));
        if let Some(reason)=report["smart_rotation_last_reason"].as_str(){
            println!("  Last path change reason: {reason}");
        }
        println!("  Valid Direct return proofs toward next scheduled handoff: {} / 2",
            report["smart_direct_proof_confirmations"].as_u64().unwrap_or(0));
    }
    if let Some(age)=report["auto_last_switch_age_seconds"].as_i64().filter(|age|*age>=0) {
        println!("  Last ICMP path switch: {age}s ago");
    }
    if let (Some(sent), Some(received), Some(dropped))=(
        report["icmp_fragmented_datagrams"].as_u64(),
        report["icmp_reassembled_datagrams"].as_u64(),
        report["icmp_fragment_drops"].as_u64()) {
        println!("  Segmented outgoing / reassembled inbound messages: {sent} / {received}");
        println!("  Expired/invalid incomplete assemblies: {dropped}");
        if let (Some(parity), Some(recovered))=(
            report["icmp_fec_parity_generated"].as_u64(),
            report["icmp_fec_recovered_datagrams"].as_u64()) {
            println!("  Bounded UDP repair parity generated: {parity}");
            println!("  UDP datagrams recovered after one missing fragment: {recovered}");
        }
    }
    println!("  Recovery handshakes: {}",report["recoveries"]);
    println!("  Queued data frames: {}",report["pending_packets"]);
    println!("  Expired/overflow data frames: {}",report["expired_or_overflow_packets"]);
    if report["icmp_direction"].as_str()==Some("reverse") {
        println!("  Reverse queued frames / bytes: {} / {}",report["reverse_queue_packets"],report["reverse_queue_bytes"]);
        println!("  Reverse queue peak / drops: {} / {}",report["reverse_queue_peak"],report["reverse_queue_drops"]);
        println!("  Reverse oldest waiting frame: {} ms",report["reverse_oldest_queue_age_ms"]);
        println!("  Reverse last/max send queue delay: {} / {} ms",report["reverse_last_delivery_delay_ms"],report["reverse_max_delivery_delay_ms"]);
        println!("  Reverse delivered/slow (>250ms) frames: {} / {}",report["reverse_delivered_frames"],report["reverse_delayed_frames"]);
        println!("  Reverse very slow (>1s) frames: {}",report["reverse_very_delayed_frames"]);
        println!("  Reverse successful send queue delay mean/P95 (last 128): {} / {} ms ({} samples)",
            report["reverse_mean_delivery_delay_ms"],report["reverse_p95_delivery_delay_ms"],report["reverse_delivery_delay_samples"]);
        if let Some(age)=report["reverse_last_delivery_age_seconds"].as_i64().filter(|v|*v>=0) {
            if age>60 {
                println!("  NOTE: these queue delay samples are HISTORICAL (last delivery {age}s ago), not live lag.");
            } else {
                println!("  Last successful queued Reverse delivery: {age}s ago");
            }
        }
        println!("  Reverse ICMP reply write failures: {}",report["reverse_write_failures"]);
        println!("  Filtered kernel PTR4 Echo reflections: {}",report["reverse_poll_echo_reflections"]);
        println!("  Filtered exact PTD4 DATA Echo reflections: {}",report["reverse_data_echo_reflections"]);
        println!("  Filtered exact PTD4 PING Echo reflections: {}",report["reverse_ping_echo_reflections"]);
        println!("  Filtered exact PTD4 other Echo reflections: {}",report["reverse_other_echo_reflections"]);
        println!("  PTD4 reflection cache expired / capacity evictions: {} / {}",
            report["reverse_echo_cache_expired"],report["reverse_echo_cache_capacity_evicted"]);
        println!("  Outbound PTD4 reflection cache entries: {}",report["reverse_data_echo_cache_entries"]);
        if let Some(drops)=report["reverse_replay_capacity_rejections"].as_u64() {
            println!("  Reverse poll replay-cache capacity rejections: {drops}");
        }
        if let Some(ms)=report["reverse_poll_interval_ms"].as_u64().filter(|v|*v>0) {
            println!("  Adaptive reverse polling interval: {ms} ms");
        }
        if let Some(ms)=report["reverse_last_outbound_data_age_ms"].as_i64().filter(|v|*v>=0) {
            println!("  Last successful Foreign->Iran DATA send: {ms} ms ago");
        }
        if let Some(age)=report["reverse_last_data_age_seconds"].as_i64().filter(|v|*v>=0) {
            println!("  Last authenticated reverse data frame: {age}s ago");
        }
    }
    Ok(())
}

fn show_adaptive_status() -> Result<()> {
    match fs::read(PERF_STATUS) {
        Ok(bytes) => {
            let data: Value = serde_json::from_slice(&bytes)?;
            let mode=load_config().ok()
                .and_then(|cfg|cfg["transport"].as_str().map(str::to_owned))
                .unwrap_or_else(||"unknown".into());
            println!("Adaptive Performance (Go core, automatic)");
            println!("  Profile: {}", data["profile"].as_str().unwrap_or("unknown"));
            println!("  RTT: {} ms", data["rtt_ms"]);
            println!("  Jitter: {} ms", data["jitter_ms"]);
            println!("  Probe loss estimate: {}", data["probe_loss_estimate"]);
            println!("  Samples: {}", data["rtt_samples"]);
            if let Some(age)=data["last_rtt_sample_age_seconds"].as_i64() {
                println!("  Last authenticated RTT sample: {}",
                    if age<0 {"never".into()}else{format!("{age}s ago")});
            } else {
                println!("  WARNING: Go core does not report RTT sample freshness.");
            }
            if mode=="tcp" {
                println!("  Next TCP retransmission: {} ms", data["next_tcp_resend_ms"]);
                println!("  Next TCP window: {}", data["next_tcp_window"]);
                println!("  Existing TCP streams retain native BB congestion control.");
            } else if mode=="udp" {
                let cfg=load_config()?;
                let buffer=get_number(&cfg,"udp_buf",0)?;
                let idle=get_number(&cfg,"timeout",60)?;
                println!("  UDP receive/send buffer requested: {}",
                    if buffer==0{"OS default".into()}else{format!("{buffer} bytes")});
                println!("  UDP idle timeout: {idle}s");
                println!("  Actual kernel queue sizes can be lower than requested.");
                println!("  TCP retransmission/window values do not apply to UDP.");
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            println!("No performance samples yet. Run the client Go service to start automatic measurement.");
            Ok(())
        }
        Err(err) => Err(Box::new(err)),
    }
}

fn logs(lines: &str) -> Result<()> {
    let count: u32 = lines.parse()?;
    if count == 0 || count > 10_000 {
        return Err(failure("lines must be 1..10000"));
    }
    let status = Command::new("journalctl")
        .args(["-u", "pingtunnel.service", "-n", &count.to_string(), "--no-pager"])
        .stdout(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(failure("journalctl failed."));
    }
    Ok(())
}

fn main_inner()->Result<()>{
    let args:Vec<String>=env::args().skip(1).collect();
    if args.is_empty()||args[0]=="menu"{
        let out=Command::new("id").arg("-u").output()?;
        if String::from_utf8_lossy(&out.stdout).trim()!="0"{
            let code=Command::new("sudo").arg(env::current_exe()?).arg("menu").status()?;
            if !code.success(){return Err(failure("Could not elevate menu"));}
            return Ok(());
        }
    }
    let sub=args.first().map(String::as_str).unwrap_or("menu");
    match sub{
        "menu"=>menu(),
        "setup"=>setup::wizard(),
        "key"=>display_pair_key(),
        "route"=>{
            let action=args.get(1).map(String::as_str).unwrap_or("show");
            if args.len()>2 {return Err(failure("Usage: pingtunnel route [show|auto-reverse|auto-direct|manual-reverse|manual-direct]"));}
            if action=="show" {
                let cfg=load_config()?;
                let policy=get_string(&cfg,"icmp_direction").unwrap_or("auto");
                println!("Configured route policy: {}",route_policy_label(policy));
                println!("The policy must match on both Iran and Foreign VPSs.");
                Ok(())
            } else {route_policy_set(action)}
        },
        "services"=>services_cli(&args[1..]),
        "performance"=>show_adaptive_status(),
        "security"=>show_security_status(),
        "health"=>{
            if args.len()>2 || args.get(1).is_some_and(|s|s!="--peer") {
                return Err(failure("Usage: pingtunnel health [--peer]"));
            }
            show_health(args.get(1).map(String::as_str)==Some("--peer"))
        },
        "service-install"=>service_install(),
        "validate"=>{load_config()?;println!("Version-3 configuration valid");Ok(())},
        "dry-run"=>run_core(true),
        "run"|"--run"=>run_core(false),
        "start"|"stop"|"restart"=>{root_required()?;run_systemctl(&[sub,"pingtunnel.service"])},
        "status"=>run_systemctl(&["status","pingtunnel.service","--no-pager"]),
        "logs"=>logs(args.get(1).map(String::as_str).unwrap_or("100")),
        "update"=>update(),
        "uninstall"=>{
            if args.len()>2 || args.get(1).is_some_and(|s|s!="--purge") {
                return Err(failure("Usage: pingtunnel uninstall [--purge]"));
            }
            uninstall(args.get(1).map(String::as_str)==Some("--purge"))
        },
        "version"|"--version"=>{println!("{}",env!("CARGO_PKG_VERSION"));Ok(())},
        "help"|"--help"|"-h"=>{help();Ok(())},
        _=>{help();Err(failure(format!("Unknown command: {sub}")))}
    }
}

fn main() {
    if let Err(e) = main_inner() {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn uninstall_helpers_remove_files_and_directories_idempotently() {
        let root = std::env::temp_dir().join(format!("pingtunnel-uninstall-test-{}", process::id()));
        let file = root.join("stale-runtime.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&file, b"stale").unwrap();
        remove_known_file(file.to_str().unwrap()).unwrap();
        remove_known_file(file.to_str().unwrap()).unwrap();
        assert!(!file.exists());
        remove_known_dir(root.to_str().unwrap()).unwrap();
        remove_known_dir(root.to_str().unwrap()).unwrap();
    }
    fn conf(region:&str,protocol:&str,port:u16)->Value{
        json!({"schema_version":3,"region":region,"peer_ip":"198.51.100.45",
            "pair_key":STANDARD.encode([7u8;32]),
            "transport":protocol,"port":port,"memory_mb":0,"autostart":true})
    }
    #[test]
    fn role_independent_pair_identity_and_authentication(){
        let iran=conf("iran","udp",444);
        let foreign=conf("foreign","udp",8443);
        assert_eq!(numeric_auth_code(get_string(&iran,"pair_key").unwrap()).unwrap(),
                   numeric_auth_code(get_string(&foreign,"pair_key").unwrap()).unwrap());
        assert_eq!(go_core_config(&iran).unwrap()["listen"],":444");
        assert_eq!(go_core_config(&iran).unwrap()["icmp_direction"],"auto");
        let remote=go_core_config(&foreign).unwrap();
        assert_eq!(remote["fixed_target"],"127.0.0.1:8443");
        assert_eq!(remote["forward_protocol"],0);
        assert_eq!(remote["icmp_direction"],"auto");
        assert_eq!(remote["peer_ip"],"198.51.100.45");
        assert!(remote.get("tcp_bs").is_none());
    }
    #[test]
    fn route_policy_values_preserve_wire4_and_refuse_unsafe_choices() {
        for policy in ["auto","auto_direct","direct","reverse"] {
            let mut c=conf("iran","udp",444);
            c["icmp_direction"]=json!(policy);
            assert!(validate(&c).is_ok(),"policy {policy}");
            assert_eq!(go_core_config(&c).unwrap()["icmp_direction"],policy);
        }
        let mut c=conf("foreign","udp",8443);
        c["icmp_direction"]=json!("manual");
        assert!(validate(&c).is_err());
        c["icmp_direction"]=json!("auto_reverse");
        assert!(validate(&c).is_err());
        c["icmp_direction"]=json!("auto_direct");
        assert_eq!(go_core_config(&c).unwrap()["icmp_direction"],"auto_direct");
        assert_eq!(route_policy_label("direct"),"MANUAL Direct only");
        assert_eq!(route_policy_label("auto"),"AUTO Reverse first");
    }
    #[test]
    fn authenticated_peer_health_gate_is_explicit() {
        let mut report=json!({"state":"handshaking","last_valid_age_seconds":0});
        assert!(!recent_authenticated_peer(&report,35));
        report["state"]=json!("authenticated");
        assert!(recent_authenticated_peer(&report,35));
        report["last_valid_age_seconds"]=json!(35);
        assert!(recent_authenticated_peer(&report,35));
        report["last_valid_age_seconds"]=json!(36);
        assert!(!recent_authenticated_peer(&report,35));
        report["last_valid_age_seconds"]=json!(-1);
        assert!(!recent_authenticated_peer(&report,35));
        report.as_object_mut().unwrap().remove("last_valid_age_seconds");
        assert!(!recent_authenticated_peer(&report,35));
    }
    #[test]
    fn no_legacy_or_unencrypted_fallback(){
        let legacy=json!({"type":"client","key":"123456","tcp":1,"l_port":443,"server":"198.51.100.45"});
        assert!(validate(&legacy).is_err());
        let mut c=conf("iran","tcp",443);
        c.as_object_mut().unwrap().remove("pair_key");
        assert!(validate(&c).is_err());
        assert!(go_core_config(&c).is_err());
    }
    #[test]
    fn performance_overrides_are_validated_and_forwarded() {
        let mut cfg=conf("iran","tcp",443);
        cfg["tcp_bs"]=json!(524288);
        cfg["tcp_mw"]=json!(4096);
        cfg["tcp_rst"]=json!(850);
        cfg["timeout"]=json!(90);
        let go=go_core_config(&cfg).unwrap();
        assert_eq!(go["tcp_bs"],524288);
        assert_eq!(go["tcp_mw"],4096);
        assert_eq!(go["tcp_rst"],850);
        assert_eq!(go["timeout"],90);
        cfg["tcp_mw"]=json!(20001);
        assert!(validate(&cfg).is_err());
    }
    #[test]
    fn experimental_packet_features_are_disabled_by_default() {
        let iran=conf("iran","udp",444);
        let foreign=conf("foreign","udp",444);
        for cfg in [&iran,&foreign] {
            let go=go_core_config(cfg).unwrap();
            assert_eq!(go["icmp_segment"],false);
            assert_eq!(go["udp_fec"],false);
        }
        let mut cfg=iran.clone();
        cfg["udp_fec"]=json!(true);
        assert!(validate(&cfg).is_err());
        cfg["icmp_segment"]=json!(true);
        assert!(validate(&cfg).is_ok());
        assert_eq!(go_core_config(&cfg).unwrap()["udp_fec"],true);
        cfg["udp_fec"]=json!("yes");
        assert!(validate(&cfg).is_err());
    }
    #[test]
    fn udp_socket_queue_override_is_validated_and_client_only() {
        let mut cfg=conf("iran","udp",444);
        assert!(go_core_config(&cfg).unwrap().get("udp_buf").is_none());
        cfg["udp_buf"]=json!(524288);
        cfg["timeout"]=json!(90);
        let go=go_core_config(&cfg).unwrap();
        assert_eq!(go["tcp"],0);
        assert_eq!(go["udp_buf"],524288);
        assert_eq!(go["timeout"],90);
        assert!(go.get("tcp_mw").is_none());
        cfg["udp_buf"]=json!(10);
        assert!(validate(&cfg).is_err());
        cfg["udp_buf"]=json!(2097153);
        assert!(validate(&cfg).is_err());
        let mut server=conf("foreign","udp",444);
        server["udp_buf"]=json!(524288);
        assert!(go_core_config(&server).unwrap().get("udp_buf").is_none());
    }
    #[test]
    fn mismatched_inputs_rejected(){
        let mut c=conf("foreign","tcp",443);
        c["peer_ip"]=json!("127.0.0.1");
        assert!(validate(&c).is_err());
        c["peer_ip"]=json!("198.51.100.45");
        c["port"]=json!(0);
        assert!(validate(&c).is_err());
    }
    #[test]
    fn mixed_multi_port_maps_both_protocols_and_preserves_queue_profile() {
        let services=json!([
            {"id":"S01","protocol":"tcp","iran_port":443,"foreign_port":9443,"enabled":true},
            {"id":"S02","protocol":"udp","iran_port":443,"foreign_port":8443,"enabled":true}
        ]);
        let mut iran=conf("iran","udp",444);
        iran["services"]=services.clone();
        iran["tcp_bs"]=json!(524288);
        iran["tcp_mw"]=json!(4096);
        iran["tcp_rst"]=json!(850);
        iran["udp_buf"]=json!(524288);
        assert!(validate(&iran).is_ok());
        let local=go_core_config(&iran).unwrap();
        assert_eq!(local["tcp"],0);
        assert_eq!(local["listen"],":443");
        assert_eq!(local["target"],"msm-service:S01");
        assert_eq!(local["tcp_bs"],524288);
        assert_eq!(local["tcp_mw"],4096);
        assert_eq!(local["tcp_rst"],850);
        assert_eq!(local["udp_buf"],524288);

        let mut foreign=conf("foreign","udp",444);
        foreign["services"]=services;
        let remote=go_core_config(&foreign).unwrap();
        assert_eq!(remote["forward_protocol"],0);
        assert_eq!(remote["fixed_target"],"127.0.0.1:9443");
        assert_eq!(remote["services"][1]["protocol"],"udp");
        assert_eq!(remote["peer_ip"],"198.51.100.45");
    }

    #[test]
    fn multi_port_rejects_bad_ids_duplicates_and_missing_protocol() {
        let mut cfg=conf("iran","tcp",443);
        cfg["services"]=json!([
            {"id":"S01","protocol":"tcp","iran_port":443,"foreign_port":443,"enabled":true},
            {"id":"S02","protocol":"udp","iran_port":444,"foreign_port":444,"enabled":true}
        ]);
        assert!(validate(&cfg).is_ok());
        cfg["services"][1]["id"]=json!("S01");
        assert!(validate(&cfg).is_err());
        cfg["services"][1]["id"]=json!("S02");
        cfg["services"][1]["protocol"]=json!("tcp");
        assert!(validate(&cfg).is_err());
        cfg["services"][1]["protocol"]=json!("udp");
        cfg["services"][1]["iran_port"]=json!(0);
        assert!(validate(&cfg).is_err());
        cfg["services"]=json!((1..=13).map(|i|json!({"id":format!("S{:02}",i.min(12)),"protocol":if i%2==0{"udp"}else{"tcp"},"iran_port":1000+i,"foreign_port":2000+i,"enabled":true})).collect::<Vec<_>>());
        assert!(validate(&cfg).is_err());
    }

}
