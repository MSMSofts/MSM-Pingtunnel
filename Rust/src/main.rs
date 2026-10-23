use serde_json::{json, Value};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

mod setup;
mod menu_ui;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONFIG: &str = "/opt/pingtunnel/conf/config.json";
const CORE: &str = "/opt/pingtunnel/bin/pingtunnel";
const CORE_CONFIG: &str = "/run/pingtunnel-core.json";
const PERF_STATUS: &str = "/run/pingtunnel-performance.json";
const SECURITY_STATUS: &str = "/run/pingtunnel-security.json";
const UNIT: &str = "/etc/systemd/system/pingtunnel.service";
const DROPIN: &str = "/etc/systemd/system/pingtunnel.service.d/memory.conf";
const UPDATE_URL: &str =
    "https://raw.githubusercontent.com/MSMSofts/Pingtunnel_manager/main/Source/install.sh";

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
    if !(1..=65535).contains(&get_number(cfg,"port",0)?){return Err(failure("invalid local port"));}
    let secret=get_string(cfg,"pair_key").ok_or_else(||failure("missing pairing key"))?;
    let bytes=STANDARD.decode(secret).map_err(|_|failure("pairing key not base64"))?;
    if bytes.len()!=32||STANDARD.encode(&bytes)!=secret{return Err(failure("pairing key must be 32 random bytes in canonical base64"));}
    if get_number(cfg,"memory_mb",0)?>1_048_576{return Err(failure("invalid memory limit"));}
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
        "tcp":protocol,"noprint":1,"nolog":1
    });
    if region=="iran"{
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
StartLimitIntervalSec=60
StartLimitBurst=6

[Service]
Type=simple
ExecStart=/usr/local/bin/pingtunnel run
WorkingDirectory=/opt/pingtunnel
Restart=on-failure
RestartSec=3
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

fn uninstall(purge: bool) -> Result<()> {
    root_required()?;
    println!("Stop and remove the Pingtunnel service and binaries?");
    if prompt("Confirm (type YES)", "no")? != "YES" {
        println!("Cancelled.");
        return Ok(());
    }
    let _ = run_systemctl(&["stop", "pingtunnel.service"]);
    let _ = run_systemctl(&["disable", "pingtunnel.service"]);
    for path in [UNIT, DROPIN, "/etc/systemd/system/pingtunnel.service.d"] {
        let p = Path::new(path);
        if p.is_file() {
            fs::remove_file(p)?;
        } else if p.is_dir() {
            let _ = fs::remove_dir(p);
        }
    }
    let _ = run_systemctl(&["daemon-reload"]);
    let _ = fs::remove_file("/usr/local/bin/pingtunnel");
    let _ = fs::remove_file("/usr/local/bin/install_pingtunnel.py");
    let _ = fs::remove_file("/run/pingtunnel.pid");
    let _ = fs::remove_file("/opt/pingtunnel/run_pingtunnel.py");
    if purge {
        let _ = fs::remove_dir_all("/opt/pingtunnel");
        let _ = fs::remove_dir_all("/var/log/pingtunnel");
        println!("Removed application, configuration, and logs.");
    } else {
        let _ = fs::remove_dir_all("/opt/pingtunnel/bin");
        println!("Uninstalled. Kept /opt/pingtunnel/conf/config.json and existing logs.");
    }
    Ok(())
}

fn help(){
    println!("Pingtunnel Manager v{} — pairing v3",env!("CARGO_PKG_VERSION"));
    println!("  pingtunnel            Unified menu");
    println!("  pingtunnel setup      Five questions on each VPS");
    println!("  pingtunnel key        Show existing pairing key (root only)");
    println!("  pingtunnel validate | performance | security | health | dry-run");
    println!("  pingtunnel start | stop | restart | status | logs [lines]");
    println!("  pingtunnel update | uninstall [--purge]");
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

fn menu()->Result<()>{
    root_required()?;
    loop{
        let cfg=load_config().ok();
        let service_state=current_service_state();
        let view=menu_ui::MenuView {
            version: env!("CARGO_PKG_VERSION"),
            region:cfg.as_ref().and_then(|v|get_string(v,"region")).unwrap_or("unknown"),
            peer:cfg.as_ref().and_then(|v|get_string(v,"peer_ip")).unwrap_or("-"),
            transport:cfg.as_ref().and_then(|v|get_string(v,"transport")).unwrap_or("-"),
            port:cfg.as_ref().and_then(|v|v.get("port")).and_then(Value::as_u64).and_then(|n|u16::try_from(n).ok()),
            service:&service_state,
            configured:cfg.is_some(),
        };
        // No terminal control codes for pipes, logs, dumb terminals, or NO_COLOR.
        print!("{}",menu_ui::render(
            &view,menu_ui::supports_color(),menu_ui::supports_unicode()
        ));
        let choice=prompt("Choose option (1-14)",if cfg.is_some(){"1"}else{"6"})?;
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
            "14"=>show_health(),
            _=>{println!("Invalid choice. Select a number from 1 to 14.");continue}
        };
        if let Err(e)=action{eprintln!("Operation failed: {e}");}
    }
}

fn show_health() -> Result<()> {
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
    println!("Security session state: {}",status["state"].as_str().unwrap_or("unknown"));
    println!("Last authenticated peer traffic: {} seconds ago (may be idle).",status["last_valid_age_seconds"]);
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
    println!("  Last valid message age: {} seconds",report["last_valid_age_seconds"]);
    println!("  Pending key renegotiation: {}",report["pending_rekey"]);
    println!("  Replays rejected: {}",report["replay_drops"]);
    println!("  Authentication failures: {}",report["authentication_failures"]);
    println!("  Recovery handshakes: {}",report["recoveries"]);
    println!("  Queued data frames: {}",report["pending_packets"]);
    println!("  Expired/overflow data frames: {}",report["expired_or_overflow_packets"]);
    Ok(())
}

fn show_adaptive_status() -> Result<()> {
    match fs::read(PERF_STATUS) {
        Ok(bytes) => {
            let data: Value = serde_json::from_slice(&bytes)?;
            println!("Adaptive Performance (Go core, automatic)");
            println!("  Profile: {}", data["profile"].as_str().unwrap_or("unknown"));
            println!("  RTT: {} ms", data["rtt_ms"]);
            println!("  Jitter: {} ms", data["jitter_ms"]);
            println!("  Probe loss estimate: {}", data["probe_loss_estimate"]);
            println!("  Next TCP retransmission: {} ms", data["next_tcp_resend_ms"]);
            println!("  Next TCP window: {}", data["next_tcp_window"]);
            println!("  Samples: {}", data["rtt_samples"]);
            println!("  Existing TCP streams retain native BB congestion control.");
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
        "performance"=>show_adaptive_status(),
        "security"=>show_security_status(),
        "health"=>show_health(),
        "service-install"=>service_install(),
        "validate"=>{load_config()?;println!("Version-3 configuration valid");Ok(())},
        "dry-run"=>run_core(true),
        "run"|"--run"=>run_core(false),
        "start"|"stop"|"restart"=>{root_required()?;run_systemctl(&[sub,"pingtunnel.service"])},
        "status"=>run_systemctl(&["status","pingtunnel.service","--no-pager"]),
        "logs"=>logs(args.get(1).map(String::as_str).unwrap_or("100")),
        "update"=>update(),
        "uninstall"=>uninstall(args.get(1).map(String::as_str)==Some("--purge")),
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
        let remote=go_core_config(&foreign).unwrap();
        assert_eq!(remote["fixed_target"],"127.0.0.1:8443");
        assert_eq!(remote["forward_protocol"],0);
        assert_eq!(remote["peer_ip"],"198.51.100.45");
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
    fn mismatched_inputs_rejected(){
        let mut c=conf("foreign","tcp",443);
        c["peer_ip"]=json!("127.0.0.1");
        assert!(validate(&c).is_err());
        c["peer_ip"]=json!("198.51.100.45");
        c["port"]=json!(0);
        assert!(validate(&c).is_err());
    }
}
