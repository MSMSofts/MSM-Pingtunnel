use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONFIG: &str = "/opt/pingtunnel/conf/config.json";
const CORE: &str = "/opt/pingtunnel/bin/pingtunnel";
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

fn run_core(dry_run: bool) -> Result<()> {
    let cfg = load_config()?;
    let bin = core_binary(&cfg);
    if !bin.is_file() {
        return Err(failure(format!("Core binary is missing: {}", bin.display())));
    }
    let args = core_args(&cfg)?;
    if dry_run {
        let shown: Vec<String> = args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                if i > 0 && args[i - 1] == "-key" {
                    "[REDACTED]".to_owned()
                } else {
                    arg.clone()
                }
            })
            .collect();
        println!("{} {}", bin.display(), shown.join(" "));
        return Ok(());
    }

    // exec() replaces this Rust process with the Go core in the SAME PID.
    // There is no resident Rust or Python monitor.
    let error = Command::new(&bin).args(&args).exec();
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
    println!("Saved {CONFIG} (mode 0600). Apply changes: sudo pingtunnel service-install && sudo pingtunnel restart");
    Ok(())
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
    println!("Native systemd unit installed; no resident manager process.");
    Ok(())
}

fn edit_config() -> Result<()> {
    root_required()?;
    let editor = env::var("EDITOR").unwrap_or_else(|_| "nano".to_owned());
    if !editor.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c)) {
        return Err(failure("EDITOR must be a single executable path/name."));
    }
    let status = Command::new(editor).arg(CONFIG).status()?;
    if !status.success() {
        return Err(failure("Editor failed."));
    }
    load_config()?;
    fs::set_permissions(CONFIG, fs::Permissions::from_mode(0o600))?;
    println!("Config valid. Apply with sudo pingtunnel service-install && sudo pingtunnel restart.");
    Ok(())
}

fn update() -> Result<()> {
    root_required()?;
    let temp = env::temp_dir().join(format!("pingtunnel-update-{}.sh", process::id()));
    let status = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error", "--retry", "3", UPDATE_URL, "-o"])
        .arg(&temp)
        .status()?;
    if !status.success() {
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
    println!("  pingtunnel configure         Configure server/client (preserves legacy JSON)");
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
    loop {
        println!("\n=== Pingtunnel Manager (Rust) ===");
        println!("1) Status   2) Start   3) Stop   4) Restart");
        println!("5) Logs     6) Configure   7) Update   8) Exit");
        let choice = prompt("Choose", "1")?;
        match choice.as_str() {
            "1" => run_systemctl(&["status", "pingtunnel.service", "--no-pager"]),
            "2" => run_systemctl(&["start", "pingtunnel.service"]),
            "3" => run_systemctl(&["stop", "pingtunnel.service"]),
            "4" => run_systemctl(&["restart", "pingtunnel.service"]),
            "5" => logs("100"),
            "6" => configure(),
            "7" => update(),
            "8" => return Ok(()),
            _ => {
                println!("Unknown option.");
                continue;
            }
        }?;
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
    let sub = args.first().map(String::as_str).unwrap_or("menu");
    match sub {
        "menu" => menu(),
        "configure" | "config" => configure(),
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
