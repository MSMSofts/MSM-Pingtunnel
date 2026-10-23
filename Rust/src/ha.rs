//! Optional high-availability TCP forwarding for the client role.
//! Existing TCP streams remain pinned to their original core during route switches.
//! An abruptly lost Go/ICMP path cannot migrate TCP state; only NEW streams fail over.

use crate::{as_string, atomic_save, core_binary, failure, get_number, get_string, root_required, Result};
use serde_json::{json, Value};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};

mod udp;

const RUNTIME: &str = "/run/pingtunnel-ha";
const STATUS: &str = "/run/pingtunnel-ha/status.json";
const MIN_ROUTES: usize = 2;
const MAX_ROUTES: usize = 4;

#[derive(Clone, Debug)]
struct Route {
    name: String,
    server: String,
    data_port: u16,
    probe_port: u16,
}

#[derive(Clone, Debug)]
struct Settings {
    listen: SocketAddr,
    target: String,
    key: i64,
    tcp: bool,
    udp_idle_seconds: u64,
    routes: Vec<Route>,
    probe_target: String,
    probe_domain: String,
    probe_enabled: bool,
    check_seconds: u64,
    failure_threshold: u32,
    success_threshold: u32,
    switch_streak: u32,
    cooldown_seconds: u64,
    max_connections: usize,
}

#[derive(Clone, Debug, Default)]
struct Health {
    good: bool,
    success_streak: u32,
    failure_streak: u32,
    better_streak: u32,
    last_ms: Option<u64>,
    smoothed_ms: Option<f64>,
}

struct RouterState {
    active: Option<usize>,
    switches: u64,
    last_switch: Instant,
    health: Vec<Health>,
}

pub(crate) fn is_enabled(cfg: &Value) -> bool {
    cfg.get("ha")
        .and_then(|ha| ha.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && !host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

fn valid_target(s: &str) -> bool {
    if let Some((host, port)) = s.rsplit_once(':') {
        valid_host(host) && port.parse::<u16>().map(|v| v > 0).unwrap_or(false)
    } else {
        false
    }
}

fn parse(cfg: &Value) -> Result<Settings> {
    let ha = cfg.get("ha").ok_or_else(|| failure("Missing ha configuration."))?;
    if !is_enabled(cfg) {
        return Err(failure("ha.enabled must be true."));
    }
    if get_string(cfg, "type") != Some("client") {
        return Err(failure("HA mode supports client role only."));
    }
    let protocol = get_number(cfg, "tcp", 1)?;
    if protocol > 1 {
        return Err(failure("HA tcp must be 1 (TCP) or 0 (UDP)."));
    }
    let listen_port = get_number(cfg, "l_port", 0)?;
    if listen_port == 0 || listen_port > 65535 {
        return Err(failure("HA l_port must be 1..65535."));
    }
    let key = cfg.get("key").and_then(as_string).ok_or_else(|| failure("Missing key."))?;
    let key: i64 = key.parse().map_err(|_| failure("HA requires a numeric Pingtunnel key."))?;
    if !(0..=2_147_483_647).contains(&key) {
        return Err(failure("Pingtunnel key must be in 0..2147483647."));
    }
    let target = get_string(cfg, "target")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", get_string(cfg, "server").unwrap_or(""), listen_port));
    if !valid_target(&target) {
        return Err(failure("Client target must be a valid host:port."));
    }

    let bind_host = ha.get("listen_host").and_then(Value::as_str).unwrap_or("127.0.0.1");
    let bind_ip: IpAddr = bind_host.parse().map_err(|_| failure("ha.listen_host must be an IP."))?;
    // Restrict to explicit IPv4 addresses: Go route internal sockets are IPv4 loopback.
    if !matches!(bind_ip, IpAddr::V4(_)) {
        return Err(failure("ha.listen_host currently supports IPv4 only."));
    }
    let listen = SocketAddr::new(bind_ip, listen_port as u16);
    let base_data = ha.get("data_port_base").and_then(Value::as_u64).unwrap_or(36000);
    let base_probe = ha.get("probe_port_base").and_then(Value::as_u64).unwrap_or(37000);
    let endpoints = ha.get("endpoints").and_then(Value::as_array)
        .ok_or_else(|| failure("ha.endpoints must be an array."))?;
    if !(MIN_ROUTES..=MAX_ROUTES).contains(&endpoints.len()) {
        return Err(failure("Configure 2..4 independent foreign Pingtunnel endpoints."));
    }
    let mut routes = Vec::with_capacity(endpoints.len());
    let mut names = std::collections::HashSet::new();
    let mut servers = std::collections::HashSet::new();
    let mut used = std::collections::HashSet::new();
    used.insert(listen_port);
    for (i, endpoint) in endpoints.iter().enumerate() {
        let name = endpoint.get("name").and_then(Value::as_str).unwrap_or("");
        let server = endpoint.get("server").and_then(Value::as_str).unwrap_or("");
        if name.len() > 32 || name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
            return Err(failure("Each endpoint name must be 1..32 characters: a-z, 0-9, _ or -."));
        }
        if !names.insert(name.to_owned()) || !valid_host(server) || !servers.insert(server.to_owned()) {
            return Err(failure("Endpoints need unique names and distinct, valid server addresses."));
        }
        let dp = base_data.checked_add(i as u64).ok_or_else(|| failure("Invalid data port base"))?;
        let pp = base_probe.checked_add(i as u64).ok_or_else(|| failure("Invalid probe port base"))?;
        if !(1024..=65535).contains(&dp) || !(1024..=65535).contains(&pp)
            || !used.insert(dp) || !used.insert(pp)
        {
            return Err(failure("HA listen, data and probe ports must be distinct (1024..65535)."));
        }
        routes.push(Route {
            name: name.to_owned(), server: server.to_owned(),
            data_port: dp as u16, probe_port: pp as u16,
        });
    }
    let probe_enabled = ha.get("probe_enabled").and_then(Value::as_bool).unwrap_or(true);
    let probe_target = ha.get("probe_target").and_then(Value::as_str).unwrap_or("1.1.1.1:443").to_owned();
    let probe_domain = ha.get("probe_domain").and_then(Value::as_str).unwrap_or("one.one.one.one").to_owned();
    if !valid_target(&probe_target) || !valid_host(&probe_domain) {
        return Err(failure("Invalid HA probe_target or probe_domain."));
    }
    // The curl TLS probe must go to TCP/443; verify the endpoint has a compatible cert.
    if probe_enabled && !probe_target.ends_with(":443") {
        return Err(failure("Current HTTPS health probe requires probe_target port 443."));
    }
    let check_seconds = ha.get("check_seconds").and_then(Value::as_u64).unwrap_or(10);
    let failure_threshold = ha.get("failure_threshold").and_then(Value::as_u64).unwrap_or(2);
    let success_threshold = ha.get("success_threshold").and_then(Value::as_u64).unwrap_or(2);
    let switch_streak = ha.get("switch_streak").and_then(Value::as_u64).unwrap_or(3);
    let cooldown_seconds = ha.get("cooldown_seconds").and_then(Value::as_u64).unwrap_or(120);
    let max_connections = ha.get("max_connections").and_then(Value::as_u64).unwrap_or(256);
    let udp_idle_seconds = ha.get("udp_idle_seconds").and_then(Value::as_u64).unwrap_or(90);
    if !(5..=300).contains(&check_seconds) || !(1..=10).contains(&failure_threshold)
        || !(1..=10).contains(&success_threshold) || !(1..=20).contains(&switch_streak)
        || !(15..=3600).contains(&cooldown_seconds) || !(1..=10000).contains(&max_connections)
        || !(5..=3600).contains(&udp_idle_seconds) {
        return Err(failure("HA checks/thresholds/limits outside supported bounds."));
    }
    Ok(Settings {
        listen, target, key, tcp: protocol == 1, udp_idle_seconds, routes, probe_target, probe_domain, probe_enabled,
        check_seconds, failure_threshold: failure_threshold as u32,
        success_threshold: success_threshold as u32, switch_streak: switch_streak as u32,
        cooldown_seconds, max_connections: max_connections as usize,
    })
}

pub(crate) fn validate(cfg: &Value) -> Result<()> {
    if is_enabled(cfg) {
        parse(cfg)?;
    }
    Ok(())
}

pub(crate) fn setup(cfg: &mut Value) -> Result<()> {
    root_required()?;
    if get_string(cfg, "type") != Some("client") || get_number(cfg, "tcp", 1)? > 1 {
        return Err(failure("Configure a client with tcp=1 (TCP) or tcp=0 (UDP) before ha-setup."));
    }
    let primary = get_string(cfg, "server")
        .ok_or_else(|| failure("Set client server first with: sudo pingtunnel configure"))?
        .to_string();
    let mut line = String::new();
    println!("HA warm-standby setup: TCP or UDP via direct ICMP with two foreign endpoints.");
    println!("Both foreign endpoints MUST be running the Go Pingtunnel server with the same numeric key.");
    println!("Original destination and config are preserved. An HA controller adds RAM overhead.");
    println!("WARNING: the HA listener uses 0.0.0.0 (same as the previous :port binding).");
    println!("Restrict access with the firewall or set ha.listen_host=127.0.0.1.");
    println!("Primary endpoint: {primary}");
    print!("Backup Pingtunnel server IP/domain: ");
    use std::io::Write;
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut line)?;
    let backup = line.trim();
    if !valid_host(backup) || backup == primary {
        return Err(failure("Enter a distinct, valid backup server address."));
    }
    cfg["ha"] = json!({
        "enabled": true,
        "listen_host": "0.0.0.0",
        "endpoints": [
            {"name":"primary","server": primary},
            {"name":"backup","server": backup}
        ],
        "data_port_base": 36000,
        "probe_port_base": 37000,
        "probe_enabled": true,
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
    validate(cfg)?;
    crate::store_config(cfg)?;
    println!("HA configured. Apply: sudo pingtunnel service-install && sudo pingtunnel restart");
    println!("Verify the backup and watch: sudo pingtunnel ha-status");
    Ok(())
}

fn core_json(settings: &Settings, route: &Route, is_probe: bool) -> Value {
    json!({
        "type":"client",
        "listen": format!("127.0.0.1:{}", if is_probe {route.probe_port} else {route.data_port}),
        "server":route.server,
        "target": if is_probe {settings.probe_target.as_str()} else {settings.target.as_str()},
        "tcp": if is_probe || settings.tcp {1} else {0},
        "key": settings.key,
        "nolog":1,
        "noprint":1
    })
}

fn write_core_config(settings: &Settings, route: &Route, probe: bool) -> Result<PathBuf> {
    let suffix = if probe { "probe" } else { "data" };
    let file = Path::new(RUNTIME).join(format!("{}-{suffix}.json", route.name));
    let data = serde_json::to_vec(&core_json(settings, route, probe))?;
    atomic_save(&file, &data, 0o600)?;
    Ok(file)
}

async fn supervise(core: PathBuf, file: PathBuf, name: String) {
    loop {
        match Command::new(&core)
            .arg("-c").arg(&file)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
            .kill_on_drop(true).spawn()
        {
            Ok(mut child) => {
                match child.wait().await {
                    Ok(status) => eprintln!("HA: {name} core exited: {status}"),
                    Err(error) => eprintln!("HA: {name} child wait failed: {error}"),
                }
            }
            Err(error) => eprintln!("HA: {name} could not start: {error}"),
        }
        sleep(Duration::from_secs(3)).await;
    }
}

async fn probe_route(settings: &Settings, route: &Route) -> Option<u64> {
    let start = Instant::now();
    if !settings.probe_enabled {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), route.data_port);
        return timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await.ok()?.ok().map(|_| start.elapsed().as_millis() as u64);
    }
    // The dedicated Go probe tunnel has target 1.1.1.1:443 (configurable).
    // Curl checks the REMOTE TLS exchange through that tunnel, not just
    // whether the local Go client socket accepts TCP connections.
    let mapping = format!("{}:443:127.0.0.1:{}", settings.probe_domain, route.probe_port);
    let url = format!("https://{}/", settings.probe_domain);
    let ok = Command::new("curl")
        .args(["--silent", "--show-error", "--noproxy", "*", "--head",
            "--output", "/dev/null", "--connect-timeout", "3", "--max-time", "6",
            "--connect-to", &mapping, &url])
        .stdout(Stdio::null()).stderr(Stdio::null())
        .kill_on_drop(true).status().await.ok()?;
    if ok.success() {
        Some(start.elapsed().as_millis() as u64)
    } else {
        None
    }
}

fn update_health(state: &mut RouterState, index: usize, latency: Option<u64>,
                 settings: &Settings) {
    let is_startup = state.active.is_none();
    let h = &mut state.health[index];
    match latency {
        Some(ms) => {
            h.last_ms = Some(ms);
            h.smoothed_ms = Some(h.smoothed_ms.map_or(ms as f64, |v| v * 0.65 + ms as f64 * 0.35));
            h.success_streak = h.success_streak.saturating_add(1);
            h.failure_streak = 0;
            // First successful end-to-end probe can bring up the first path
            // promptly. Established routes still require repeated successes.
            if h.success_streak >= settings.success_threshold
                || (is_startup && h.success_streak > 0)
            {
                h.good = true;
            }
        }
        None => {
            h.last_ms = None;
            h.failure_streak = h.failure_streak.saturating_add(1);
            h.success_streak = 0;
            h.better_streak = 0;
            if h.failure_streak >= settings.failure_threshold {
                h.good = false;
            }
        }
    }
}

fn select_route(state: &mut RouterState, settings: &Settings, now: Instant) {
    let best = state.health.iter().enumerate()
        .filter(|(_, h)| h.good)
        .min_by(|(_, a), (_, b)| {
            a.smoothed_ms.unwrap_or(f64::MAX)
                .total_cmp(&b.smoothed_ms.unwrap_or(f64::MAX))
        })
        .map(|(idx, _)| idx);
    match (state.active, best) {
        (None, Some(index)) => change_route(state, index, now),
        (Some(active), Some(best)) if !state.health[active].good => change_route(state, best, now),
        (Some(active), Some(best)) if active != best => {
            let a = state.health[active].smoothed_ms.unwrap_or(f64::MAX);
            let b = state.health[best].smoothed_ms.unwrap_or(f64::MAX);
            let meaningful = b + 40.0 < a * 0.75;
            if meaningful && now.duration_since(state.last_switch).as_secs() >= settings.cooldown_seconds {
                state.health[best].better_streak = state.health[best].better_streak.saturating_add(1);
                if state.health[best].better_streak >= settings.switch_streak {
                    change_route(state, best, now);
                }
            } else {
                state.health[best].better_streak = 0;
            }
        }
        _ => {}
    }
}

fn change_route(state: &mut RouterState, index: usize, now: Instant) {
    if state.active != Some(index) {
        state.active = Some(index);
        state.switches += 1;
        state.last_switch = now;
        for health in &mut state.health {
            health.better_streak = 0;
        }
        eprintln!("HA: switched new flows to backend #{}", index + 1);
    }
}

fn status_json(settings: &Settings, state: &RouterState) -> Value {
    json!({
        "active":state.active.map(|i| settings.routes[i].name.clone()),
        "protocol":if settings.tcp {"tcp"} else {"udp"},
        "switches":state.switches,
        "existing_sessions":if settings.tcp {
            "TCP streams stay pinned until close"
        } else {
            "UDP flows stay pinned until idle or their route fails"
        },
        "loss_of_existing_route":if settings.tcp {
            "Established TCP sessions cannot migrate on failed ICMP route"
        } else {
            "UDP datagrams may be lost during health detection and failover"
        },
        "routes":settings.routes.iter().enumerate().map(|(i,r)| json!({
            "name":r.name, "server":r.server, "healthy":state.health[i].good,
            "last_probe_ms":state.health[i].last_ms,
            "smoothed_probe_ms":state.health[i].smoothed_ms,
            "consecutive_failures":state.health[i].failure_streak,
            "data_port":r.data_port, "probe_port":r.probe_port
        })).collect::<Vec<Value>>()
    })
}

async fn monitor(settings: Settings, state: Arc<Mutex<RouterState>>) {
    let mut ticker = interval(Duration::from_secs(settings.check_seconds));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // Run all independent path probes concurrently. A stalled foreign
        // route must not block failure detection for the other routes.
        let mut probes = JoinSet::new();
        for (i, route) in settings.routes.iter().cloned().enumerate() {
            let config = settings.clone();
            probes.spawn(async move { (i, probe_route(&config, &route).await) });
        }
        let mut measurements = Vec::with_capacity(settings.routes.len());
        while let Some(result) = probes.join_next().await {
            if let Ok((i, latency)) = result {
                measurements.push((i, latency));
            }
        }
        // Evaluate once per FULL measurement round; otherwise a 3-round
        // hysteresis could accidentally finish in 1-2 rounds.
        let snapshot = {
            let mut guard = state.lock().unwrap();
            for (i, latency) in measurements {
                update_health(&mut guard, i, latency, &settings);
            }
            select_route(&mut guard, &settings, Instant::now());
            status_json(&settings, &guard)
        };
        if let Ok(data) = serde_json::to_vec_pretty(&snapshot) {
            if let Err(error) = atomic_save(Path::new(STATUS), &data, 0o600) {
                eprintln!("HA: status write error: {error}");
            }
        }
    }
}

async fn serve_connection(mut client: TcpStream, state: Arc<Mutex<RouterState>>,
                          settings: Settings) {
    let mut indices = {
        let guard = state.lock().unwrap();
        let mut ordered = Vec::new();
        if let Some(active) = guard.active {
            if guard.health[active].good {
                ordered.push(active);
            }
        }
        for (i, health) in guard.health.iter().enumerate() {
            if health.good && !ordered.contains(&i) {
                ordered.push(i);
            }
        }
        ordered
    };
    for idx in indices.drain(..) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), settings.routes[idx].data_port);
        if let Ok(Ok(mut backend)) = timeout(Duration::from_millis(1000), TcpStream::connect(addr)).await {
            // IMPORTANT: no further reads of the active route; the chosen Go
            // client keeps running even when future sessions choose a new path.
            let _ = copy_bidirectional(&mut client, &mut backend).await;
            return;
        }
    }
    // All routes unavailable: close promptly rather than silently blackhole.
    let _ = client.shutdown().await;
}

pub(crate) fn show_status() -> Result<()> {
    let bytes = fs::read(STATUS).map_err(|_| failure(
        "No HA status available. Configure HA and start sudo pingtunnel service-install && sudo pingtunnel start."
    ))?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

pub(crate) fn run(cfg: Value) -> Result<()> {
    root_required()?;
    let settings = parse(&cfg)?;
    let core = core_binary(&cfg);
    if !core.is_file() {
        return Err(failure(format!("Missing Go Pingtunnel core: {}", core.display())));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        fs::create_dir_all(RUNTIME)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(RUNTIME, fs::Permissions::from_mode(0o700))?;
        let mut paths = Vec::new();
        for route in &settings.routes {
            paths.push((route.name.clone(), write_core_config(&settings, route, false)?, false));
            if settings.probe_enabled {
                paths.push((route.name.clone(), write_core_config(&settings, route, true)?, true));
            }
        }
        // Bind the stable public TCP listener before starting the backends.
        // UDP binds its own listening socket inside udp::serve.
        let listener = if settings.tcp {
            Some(TcpListener::bind(settings.listen).await?)
        } else {
            None
        };
        let state = Arc::new(Mutex::new(RouterState {
            active: None,
            switches: 0,
            last_switch: Instant::now(),
            health: vec![Health::default(); settings.routes.len()],
        }));
        for (name, file, probe) in paths {
            let bin = core.clone();
            let label = format!("{} {}", name, if probe { "health" } else { "data" });
            tokio::spawn(supervise(bin, file, label));
        }
        tokio::spawn(monitor(settings.clone(), state.clone()));
        if !settings.tcp {
            return udp::serve(settings, state).await;
        }
        let listener = listener.ok_or_else(|| failure("TCP listener missing"))?;
        let semaphore = Arc::new(Semaphore::new(settings.max_connections));
        eprintln!("HA TCP: listening at {} with {} warm Go endpoints",
                  settings.listen, settings.routes.len());
        loop {
            let (client, _) = listener.accept().await?;
            if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                let state = state.clone();
                let settings = settings.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_connection(client, state, settings).await;
                });
            } // At capacity, the accepted TCP connection is dropped.
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Value {
        json!({"type":"client", "tcp":1, "l_port":8080, "key":"12345",
            "target":"127.0.0.1:443",
            "ha":{"enabled":true,"endpoints":[
                {"name":"a","server":"203.0.113.1"},
                {"name":"b","server":"203.0.113.2"}]}})
    }

    #[test]
    fn validate_ha_settings() {
        let settings = parse(&cfg()).unwrap();
        assert_eq!(settings.routes.len(), 2);
        assert_eq!(settings.listen.port(), 8080);
        assert!(settings.probe_enabled);
    }

    #[test]
    fn rejects_udp_and_duplicate_paths() {
        let mut c = cfg();
        c["tcp"] = json!(0);
        assert!(parse(&c).is_err());
        c["tcp"] = json!(1);
        c["ha"]["endpoints"][1]["server"] = json!("203.0.113.1");
        assert!(parse(&c).is_err());
    }

    #[test]
    fn go_config_contains_numeric_key_without_argv_secret() {
        let s = parse(&cfg()).unwrap();
        let config = core_json(&s, &s.routes[0], false);
        assert_eq!(config["key"], 12345);
        assert_eq!(config["listen"], "127.0.0.1:36000");
        assert_eq!(config["target"], "127.0.0.1:443");
    }

    #[test]
    fn failover_does_not_require_cooldown_if_active_is_down() {
        let settings = parse(&cfg()).unwrap();
        let now = Instant::now();
        let mut state = RouterState {
            active: Some(0), switches: 0, last_switch: now,
            health: vec![Health::default(), Health::default()],
        };
        state.health[0].good = true;
        state.health[1].good = true;
        state.health[1].smoothed_ms = Some(30.0);
        state.health[0].smoothed_ms = Some(40.0);
        update_health(&mut state, 0, None, &settings);
        update_health(&mut state, 0, None, &settings);
        select_route(&mut state, &settings, now);
        assert_eq!(state.active, Some(1));
    }

    #[test]
    fn warmup_uses_first_successful_end_to_end_probe() {
        let settings = parse(&cfg()).unwrap();
        let now = Instant::now();
        let mut state = RouterState {
            active: None, switches: 0, last_switch: now,
            health: vec![Health::default(), Health::default()]
        };
        update_health(&mut state, 1, Some(52), &settings);
        select_route(&mut state, &settings, now);
        assert_eq!(state.active, Some(1));
    }

    #[test]
    fn improved_latency_requires_three_full_rounds() {
        let settings = parse(&cfg()).unwrap();
        let now = Instant::now();
        let mut state = RouterState {
            active: Some(0),
            switches: 0,
            last_switch: now - Duration::from_secs(300),
            health: vec![Health::default(), Health::default()]
        };
        state.health[0].good = true;
        state.health[0].smoothed_ms = Some(500.0);
        state.health[1].good = true;
        state.health[1].smoothed_ms = Some(80.0);
        for round in 0..settings.switch_streak {
            select_route(&mut state, &settings, now);
            if round + 1 < settings.switch_streak {
                assert_eq!(state.active, Some(0));
            }
        }
        assert_eq!(state.active, Some(1));
    }

    #[tokio::test]
    async fn existing_stream_remains_on_previous_backend_after_switch() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = backend_a.local_addr().unwrap().port();
        let b = backend_b.local_addr().unwrap().port();
        let accept_a = tokio::spawn(async move {
            let (mut c,_) = backend_a.accept().await.unwrap();
            let mut buf = [0u8; 8];
            loop {
                let n = c.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                c.write_all(&buf[..n]).await.unwrap();
            }
        });
        let accept_b = tokio::spawn(async move {
            let (mut c,_) = backend_b.accept().await.unwrap();
            let mut buf = [0u8; 8];
            let n = c.read(&mut buf).await.unwrap();
            c.write_all(&buf[..n]).await.unwrap();
        });
        let mut settings = parse(&cfg()).unwrap();
        settings.routes[0].data_port = a;
        settings.routes[1].data_port = b;
        let state = Arc::new(Mutex::new(RouterState {
            active: Some(0), switches: 0, last_switch: Instant::now(),
            health: vec![
                Health {good:true,..Default::default()},
                Health {good:true,..Default::default()}
            ]
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let s1 = state.clone();
        let cfg1 = settings.clone();
        let proxy_accept = tokio::spawn(async move {
            for _ in 0..2 {
                let (client,_) = listener.accept().await.unwrap();
                let ss = s1.clone();
                let sc = cfg1.clone();
                tokio::spawn(serve_connection(client, ss, sc));
            }
        });
        let mut first = TcpStream::connect(local).await.unwrap();
        first.write_all(b"alpha").await.unwrap();
        let mut reply = [0u8;5];
        first.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"alpha");
        {
            state.lock().unwrap().active = Some(1);
        }
        first.write_all(b"again").await.unwrap();
        first.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"again");
        let mut second = TcpStream::connect(local).await.unwrap();
        second.write_all(b"bravo").await.unwrap();
        second.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"bravo");
        drop(first);
        drop(second);
        proxy_accept.await.unwrap();
        accept_a.await.unwrap();
        accept_b.await.unwrap();
    }
}
