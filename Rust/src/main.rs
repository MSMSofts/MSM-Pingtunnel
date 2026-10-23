use serde_json::{json, Value};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

mod setup;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONFIG: &str = "/opt/pingtunnel/conf/config.json";
const CORE: &str = "/opt/pingtunnel/bin/pingtunnel";
const CORE_CONFIG: &str = "/run/pingtunnel-core.json";
const UNIT: &str = "/etc/systemd/system/pingtunnel.service";
const DROPIN: &str = "/etc/systemd/system/pingtunnel.service.d/memory.conf";
const UPDATE_URL: &str =
    "https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/install.sh";

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
    if !cfg.is_object() {
        return Err(failure("Configuration must be a JSON object."));
    }
    let role = get_string(cfg, "type").unwrap_or("server");
    if role != "server" && role != "client" {
        return Err(failure("type must be server or client."));
    }
    let key = cfg
        .get("key")
        .and_then(as_string)
        .ok_or_else(|| failure("key is required."))?;
    if key.is_empty() || key.len() > 128 || key.contains('\n') || key.contains('\0') {
        return Err(failure("key must contain 1-128 characters with no newline or NUL."));
    }
    let tcp = get_number(cfg, "tcp", 1)?;
    if tcp > 1 {
        return Err(failure("tcp must be 0 (UDP) or 1 (TCP)."));
    }
    if let Some(key) = cfg.get("crypto_key") {
        let key = key.as_str().ok_or_else(|| failure("crypto_key must be base64 text."))?;
        let bytes = STANDARD.decode(key).map_err(|_| failure("crypto_key must be base64."))?;
        if bytes.len() != 32 || STANDARD.encode(&bytes) != key {
            return Err(failure("crypto_key must be a canonical base64-encoded 32-byte random key."));
        }
    }
    if get_number(cfg, "memory_mb", 0)? > 1_048_576 {
        return Err(failure("memory_mb exceeds the supported limit."));
    }
    if role == "client" {
        let port = get_number(cfg, "l_port", 0)?;
        if !(1..=65535).contains(&port) {
            return Err(failure("Client l_port must be 1..65535."));
        }
        let server = get_string(cfg, "server").unwrap_or("");
        if server.is_empty() || server.contains(char::is_whitespace) || server.starts_with('-') {
            return Err(failure("Client server must be a valid nonempty host/IP."));
        }
        if let Some(target) = get_string(cfg, "target") {
            let (host, p) = target
                .rsplit_once(':')
                .ok_or_else(|| failure("target must be host:port (use [IPv6]:port)."))?;
            let target_port: u16 = p.parse().map_err(|_| failure("invalid target port"))?;
            if host.is_empty() || target_port == 0 || host.chars().any(char::is_whitespace) {
                return Err(failure("invalid target host or port"));
            }
        }
    }
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

// Compatibility-only: convert legacy HA configurations to the sole direct route.
// Keep the original authentication key, forwarding port, target and TCP/UDP mode.
fn strip_legacy_multi_route(cfg: &mut Value) -> bool {
    let previous_primary = cfg.get("ha")
        .and_then(|v| v.get("endpoints"))
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .and_then(|v| v.get("server"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(obj) = cfg.as_object_mut() else { return false };
    if obj.remove("ha").is_none() { return false; }
    let missing_server = obj.get("server").and_then(Value::as_str)
        .map(|v| v.trim().is_empty()).unwrap_or(true);
    if missing_server && obj.get("type").and_then(Value::as_str) == Some("client") {
        if let Some(server) = previous_primary {
            obj.insert("server".into(), Value::String(server));
        }
    }
    true
}

fn migrate_legacy_multi_route() -> Result<bool> {
    root_required()?;
    if !config_path().exists() { return Ok(false); }
    let original = fs::read(config_path())?;
    let mut cfg: Value = serde_json::from_slice(&original)?;
    if !strip_legacy_multi_route(&mut cfg) { return Ok(false); }
    validate(&cfg)?;
    // Safe one-time snapshot with restrictive permissions.
    let backup = PathBuf::from(format!("{CONFIG}.before-single-route.bak"));
    if !backup.exists() {
        atomic_save(&backup, &original, 0o600)?;
    }
    store_config(&cfg)?;
    println!("Legacy multi-route settings converted to a single direct tunnel.");
    println!("Backup: {}", backup.display());
    Ok(true)
}

fn core_binary(cfg: &Value) -> PathBuf {
    // Legacy "binary" is respected to avoid unexpectedly changing custom installs.
    if let Some(p) = get_string(cfg, "binary") {
        if Path::new(p).is_file() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(CORE)
}

fn core_args(cfg: &Value) -> Result<Vec<String>> {
    validate(cfg)?;
    let role = get_string(cfg, "type").unwrap_or("server");
    let key = cfg.get("key").and_then(as_string).ok_or_else(|| failure("missing key"))?;
    let tcp = get_number(cfg, "tcp", 1)?;
    let mut args = vec!["-type".to_owned(), role.to_owned()];
    if role == "client" {
        let port = get_number(cfg, "l_port", 0)?;
        let host = get_string(cfg, "server").unwrap_or("");
        let target = get_string(cfg, "target")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{host}:{port}")); // preserves the old manager's target
        args.extend([
            "-l".into(),
            format!(":{port}"),
            "-s".into(),
            host.into(),
            "-t".into(),
            target,
        ]);
    }
    args.extend([
        "-key".into(),
        key,
        "-noprint".into(),
        "1".into(),
        "-nolog".into(),
        "1".into(),
        "-tcp".into(),
        tcp.to_string(),
    ]);
    Ok(args)
}

// Translate the legacy manager config into the upstream Go core's JSON schema.
// Never place authentication or encryption secrets in /proc/PID/cmdline.
fn go_core_config(cfg: &Value) -> Result<Value> {
    validate(cfg)?;
    let role = get_string(cfg, "type").unwrap_or("server");
    let key: i64 = cfg.get("key").and_then(as_string)
        .ok_or_else(|| failure("Missing shared numeric authentication key"))?
        .parse().map_err(|_| failure("Shared authentication key must be numeric"))?;
    if !(0..=2147483647).contains(&key) {
        return Err(failure("Shared authentication key outside Go core's valid range"));
    }
    let mut go = json!({
        "type":role, "key":key, "tcp":get_number(cfg,"tcp",1)?,
        "nolog":1, "noprint":1
    });
    if role == "client" {
        let port = get_number(cfg,"l_port",0)?;
        let host = get_string(cfg,"server").unwrap_or("");
        let target = get_string(cfg,"target")
            .map(str::to_owned).unwrap_or_else(|| format!("{host}:{port}"));
        go["listen"] = json!(format!(":{port}"));
        go["server"] = json!(host);
        go["target"] = json!(target);
    }
    if let Some(secret) = get_string(cfg,"crypto_key") {
        go["encrypt"] = json!("auto");
        go["encrypt_key"] = json!(secret);
    }
    Ok(go)
}

fn run_core(dry_run: bool) -> Result<()> {
    let cfg = load_config()?;
    let bin = core_binary(&cfg);
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

fn configure() -> Result<()> {
    root_required()?;
    let mut cfg = if config_path().exists() {
        let data: Value = serde_json::from_slice(&fs::read(config_path())?)?;
        if !data.is_object() {
            return Err(failure("Current config is not a JSON object."));
        }
        data
    } else {
        json!({"type":"server","tcp":1,"memory_mb":0,"autostart":false})
    };
    println!("Pingtunnel Manager — configuration (existing settings are preserved)");
    let role = prompt("Role (server/client)", get_string(&cfg, "type").unwrap_or("server"))?;
    if role != "server" && role != "client" {
        return Err(failure("Role must be server or client."));
    }
    cfg["type"] = json!(role);
    if role == "client" {
        let port = get_number(&cfg, "l_port", 4000)?.to_string();
        let port = prompt("Local listening port", &port)?.parse::<u16>()?;
        if port == 0 {
            return Err(failure("Port cannot be zero."));
        }
        cfg["l_port"] = json!(port);
        let host = prompt("Pingtunnel server host/IP", get_string(&cfg, "server").unwrap_or(""))?;
        cfg["server"] = json!(host);
        let current_target = get_string(&cfg, "target").unwrap_or("");
        let target = prompt("Forward destination host:port (blank = legacy server:local-port)", current_target)?;
        if target.is_empty() {
            if let Some(map) = cfg.as_object_mut() {
                map.remove("target");
            }
        } else {
            cfg["target"] = json!(target);
        }
    }
    // Don't display existing secrets in a terminal prompt.
    let has_key = cfg.get("key").and_then(as_string).map(|s| !s.is_empty()).unwrap_or(false);
    let message = if has_key { "Key (leave blank to keep existing key)" } else { "Key (same on both peers)" };
    let entered = prompt(message, "")?;
    if !entered.is_empty() {
        cfg["key"] = json!(entered);
    } else if !has_key {
        return Err(failure("Key cannot be empty."));
    }
    let proto = get_number(&cfg, "tcp", 1)?.to_string();
    cfg["tcp"] = json!(prompt("TCP=1, UDP=0", &proto)?.parse::<u8>()?);
    let limit = get_number(&cfg, "memory_mb", 0)?.to_string();
    cfg["memory_mb"] = json!(prompt("Memory limit in MB (0=unlimited)", &limit)?.parse::<u64>()?);
    let enabled = cfg.get("autostart").and_then(Value::as_bool).unwrap_or(false);
    let auto = prompt("Start on boot (y/n)", if enabled { "y" } else { "n" })?;
    cfg["autostart"] = json!(matches!(auto.to_lowercase().as_str(), "y" | "yes"));
    store_config(&cfg)?;
    println!("Saved {CONFIG} (mode 0600). Applying changes automatically...");
    apply_config()

}

fn service_install() -> Result<()> {
    root_required()?;
    migrate_legacy_multi_route()?;
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

fn edit_config() -> Result<()> {
    root_required()?;
    let editor = env::var("EDITOR").unwrap_or_else(|_| "nano".to_owned());
    if !editor.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c)) {
        return Err(failure("EDITOR must be a single executable path/name."));
    }
    let original = fs::read(CONFIG)?;
    let status = Command::new(editor).arg(CONFIG).status()?;
    if !status.success() {
        atomic_save(&config_path(), &original, 0o600)?;
        return Err(failure("Editor failed; original config restored."));
    }
    if let Err(error) = load_config() {
        atomic_save(&config_path(), &original, 0o600)?;
        return Err(failure(format!("Edited config invalid ({error}); original restored.")));
    }
    fs::set_permissions(CONFIG, fs::Permissions::from_mode(0o600))?;
    println!("Config validated; applying new settings automatically.");
    apply_config()
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

fn help() {
    println!("Pingtunnel Manager v{} (Rust)", env!("CARGO_PKG_VERSION"));
    println!("  pingtunnel                   Interactive menu");
    println!("  pingtunnel setup             First-run automatic wizard (minimum peer details)");
    println!("  pingtunnel configure         Advanced config in menu; applies immediately");
    println!("  pingtunnel protocol          Choose TCP/UDP in menu; applies immediately");
    println!("  pingtunnel service-install   Write a native systemd unit");
    println!("  pingtunnel validate          Validate configuration");
    println!("  pingtunnel dry-run           Show the generated core command with key redacted");
    println!("  pingtunnel start|stop|restart|status");
    println!("  pingtunnel logs [lines]      Show journald entries");
    println!("  pingtunnel update            Reinstall from official repo script");
    println!("  pingtunnel edit              Edit config ($EDITOR, default nano)");
    println!("  pingtunnel uninstall [--purge]   Purge removes configuration too");
    println!("  pingtunnel run               Internal: exec() the Go tunnel core");
}

fn menu() -> Result<()> {
    root_required()?;
    if migrate_legacy_multi_route()? {
        apply_config()?;
    }
    loop {
        let installed = config_path().exists();
        println!("\n╔══════════════════════════════════════════════╗");
        println!("║       Pingtunnel Manager {}              ║", env!("CARGO_PKG_VERSION"));
        println!("╚══════════════════════════════════════════════╝");
        println!("  Topology: Iran Client -> foreign Server (one ICMP tunnel)");
        if installed {
            match load_config() {
                Ok(cfg) => {
                    let role = get_string(&cfg, "type").unwrap_or("server");
                    let protocol = if get_number(&cfg, "tcp", 1).unwrap_or(1) == 0 { "UDP" } else { "TCP" };
                    println!("  Role: {role}   Forwarded traffic: {protocol}");
                }
                Err(error) => eprintln!("  Config problem: {error}"),
            }
        } else {
            println!("  First setup: option 6 pairs your two VPS servers.");
        }
        println!("1) Status       2) Start        3) Stop         4) Restart");
        println!("5) Logs         6) Easy setup   7) Settings     8) TCP / UDP");
        println!("9) Validate    10) Update      11) Uninstall  12) Expert editor");
        println!("13) Exit");
        let choice = prompt("Choose", if installed { "1" } else { "6" })?;
        let action = match choice.as_str() {
            "1" => run_systemctl(&["status", "pingtunnel.service", "--no-pager"]),
            "2" => run_systemctl(&["start", "pingtunnel.service"]),
            "3" => run_systemctl(&["stop", "pingtunnel.service"]),
            "4" => run_systemctl(&["restart", "pingtunnel.service"]),
            "5" => logs("100"),
            "6" => setup::wizard(),
            "7" => configure(),
            "8" => setup::protocol_menu(),
            "9" => match load_config() {
                Ok(_) => { println!("Configuration OK."); Ok(()) },
                Err(error) => Err(error),
            },
            "10" => update(),
            "11" => uninstall(false),
            "12" => edit_config(),
            "13" | "q" | "Q" => return Ok(()),
            _ => {
                println!("Unknown option; choose 1..13.");
                continue;
            }
        };
        if let Err(error) = action {
            eprintln!("Operation failed: {error}");
        }
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

fn main_inner() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    // Bare "pingtunnel" always opens the interactive menu, even when invoked
    // as a regular Linux user; sudo handles only the privileged operations.
    if args.is_empty() || args[0] == "menu" {
        let output = Command::new("id").arg("-u").output()?;
        if String::from_utf8_lossy(&output.stdout).trim() != "0" {
            let status = Command::new("sudo")
                .arg(env::current_exe()?)
                .arg("menu")
                .status()?;
            if !status.success() {
                return Err(failure("Unable to elevate permissions for Pingtunnel menu."));
            }
            return Ok(());
        }
    }
    let sub = args.first().map(String::as_str).unwrap_or("menu");
    match sub {
        "menu" => menu(),
        "migrate" => { migrate_legacy_multi_route()?; Ok(()) },
        "setup" | "quick-setup" => setup::wizard(),
        "configure" | "config" => configure(),
        "protocol" => setup::protocol_menu(),
        "service-install" => service_install(),
        "validate" => {
            load_config()?;
            println!("Configuration OK.");
            Ok(())
        }
        "dry-run" => run_core(true),
        "run" | "--run" => run_core(false),
        "start" | "stop" | "restart" => {
            root_required()?;
            run_systemctl(&[sub, "pingtunnel.service"])
        }
        "status" => run_systemctl(&["status", "pingtunnel.service", "--no-pager"]),
        "logs" => logs(args.get(1).map(String::as_str).unwrap_or("100")),
        "edit" => edit_config(),
        "update" => update(),
        "uninstall" => uninstall(args.get(1).map(String::as_str) == Some("--purge")),
        "version" | "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            help();
            Ok(())
        }
        _ => {
            help();
            Err(failure(format!("Unknown command: {sub}")))
        }
    }
}

fn main() {
    if let Err(e) = main_inner() {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_keeps_primary_endpoint_and_forwarding_protocol() {
        let mut cfg = json!({
            "type":"client", "server":"foreign.example", "key":"1234",
            "l_port":4455, "target":"127.0.0.1:443", "tcp":0,
            "ha":{"enabled":true,"endpoints":[
                {"name":"primary","server":"foreign.example"},
                {"name":"backup","server":"another.example"}
            ]}
        });
        assert!(strip_legacy_multi_route(&mut cfg));
        assert!(cfg.get("ha").is_none());
        assert_eq!(cfg["server"], "foreign.example");
        assert_eq!(cfg["tcp"], 0);
        assert_eq!(cfg["l_port"], 4455);
        assert_eq!(cfg["target"], "127.0.0.1:443");
        assert!(validate(&cfg).is_ok());
        assert!(!strip_legacy_multi_route(&mut cfg));
    }

    #[test]
    fn migration_recovers_missing_client_address_from_old_primary() {
        let mut cfg = json!({
            "type":"client", "key":"1234", "l_port":4455,
            "ha":{"enabled":true,"endpoints":[{"server":"foreign.example"}]}
        });
        assert!(strip_legacy_multi_route(&mut cfg));
        assert_eq!(cfg["server"], "foreign.example");
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn direct_mode_supports_tcp_and_udp() {
        let mut cfg = json!({"type":"client","key":"1234","server":"foreign.example","l_port":4455,"tcp":1});
        assert!(validate(&cfg).is_ok());
        cfg["tcp"] = json!(0);
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn strong_encryption_mode_and_secret_redaction() {
        let secret = STANDARD.encode([23u8;32]);
        let cfg = json!({"type":"client","key":"12345","tcp":1,
            "server":"foreign.example","l_port":4455,"crypto_key":secret});
        let generated = go_core_config(&cfg).unwrap();
        assert_eq!(generated["encrypt"],"auto");
        assert_eq!(generated["encrypt_key"],secret);
        assert_eq!(generated["key"],12345);
        assert_eq!(generated["listen"],":4455");
        let mut invalid = cfg.clone();
        invalid["crypto_key"] = json!("12345");
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn legacy_configs_can_still_upgrade_without_silent_key_changes() {
        let cfg=json!({"type":"server","key":"12345"});
        let generated=go_core_config(&cfg).unwrap();
        assert!(generated.get("encrypt").is_none());
    }

    #[test]
    fn legacy_server_configuration() {
        let cfg = json!({"type":"server","key":"123456","tcp":1,"memory_mb":500});
        let args = core_args(&cfg).unwrap();
        assert_eq!(&args[..2], ["-type", "server"]);
        assert!(args.windows(2).any(|v| v == ["-key", "123456"]));
    }

    #[test]
    fn legacy_client_uses_previous_target() {
        let cfg = json!({"type":"client","key":"123456","server":"example.org","l_port":4000,"tcp":1});
        let args = core_args(&cfg).unwrap();
        assert!(args.windows(2).any(|v| v == ["-t", "example.org:4000"]));
    }

    #[test]
    fn custom_target_is_supported() {
        let cfg = json!({"type":"client","key":123456,"server":"example.org","target":"127.0.0.1:22","l_port":4000,"tcp":1});
        let args = core_args(&cfg).unwrap();
        assert!(args.windows(2).any(|v| v == ["-t", "127.0.0.1:22"]));
    }

    #[test]
    fn invalid_port_is_rejected() {
        let cfg = json!({"type":"client","key":"test","server":"host","l_port":0});
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn udp_is_preserved() {
        let cfg = json!({"type":"client","key":"test","server":"host","l_port":53,"tcp":0});
        let args = core_args(&cfg).unwrap();
        assert!(args.windows(2).any(|v| v == ["-tcp", "0"]));
    }
}
