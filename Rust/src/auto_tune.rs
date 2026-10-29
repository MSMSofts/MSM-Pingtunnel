//! One-shot, conservative tuning for the Iran-side TCP/UDP forwarding client.
//! Uses authenticated tunnel RTT/jitter and independent IPv4 echo probes.
//! Never changes pairing, security mode, peer identity, ports or ICMP direction.
use crate::{apply_config, atomic_save, failure, get_string, load_config, root_required,
    store_config, Result, CONFIG, PERF_STATUS, SECURITY_STATUS};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime};

const BACKUP: &str = "/opt/pingtunnel/conf/config.pre-autotune.json";

#[derive(Clone, Copy, Debug)]
struct Samples {
    rtt_ms: f64,
    jitter_ms: f64,
    loss: f64,
    count: usize,
}

#[derive(Debug, PartialEq)]
struct TcpPlan {
    profile: &'static str,
    buffer_bytes: u64,
    window: u64,
    resend_ms: u64,
    timeout_secs: u64,
}

fn reply_rtt(line: &str) -> Option<f64> {
    // iputils ping formats include "time=12.3 ms" and "time<1 ms".
    let portion = line.split_once("time=")
        .map(|(_, tail)| tail)
        .or_else(|| line.split_once("time<").map(|(_, tail)| tail))?;
    let millis: f64 = portion.split_whitespace().next()?.parse().ok()?;
    if millis.is_finite() && (0.0..60000.0).contains(&millis) {
        Some(millis.max(0.1))
    } else {
        None
    }
}

fn summarize(replies: &[f64], sent: usize) -> Option<Samples> {
    if replies.len() < 3 || sent == 0 { return None; }
    let rtt_ms = replies.iter().sum::<f64>() / replies.len() as f64;
    let jitter_ms = replies.windows(2).map(|p| (p[1]-p[0]).abs()).sum::<f64>()
        / (replies.len()-1) as f64;
    Some(Samples {
        rtt_ms, jitter_ms,
        loss: 1.0 - (replies.len().min(sent) as f64 / sent as f64),
        count: replies.len(),
    })
}

fn probe(peer: &str, size: u16, count: usize) -> Option<Samples> {
    // No shell, no externally supplied arguments other than a validated IPv4.
    // Deadline bounds even a completely blocked ICMP path.
    let output = Command::new("ping")
        .args(["-4", "-n", "-c"]).arg(count.to_string())
        .args(["-i", "0.3", "-W", "2", "-w", "8", "-s"])
        .arg(size.to_string()).arg(peer).output().ok()?;
    let replies: Vec<f64> = String::from_utf8_lossy(&output.stdout)
        .lines().filter_map(reply_rtt).collect();
    summarize(&replies, count)
}

fn fresh_status(path: &str, max_age_secs: u64) -> Option<Value> {
    if fs::metadata(path).ok()?.modified().ok()?.elapsed().ok()?.as_secs() > max_age_secs {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn require_authenticated_path() -> Result<()> {
    let value = fresh_status(SECURITY_STATUS, 12)
        .ok_or_else(|| failure("No fresh Go security heartbeat; start the tunnel first."))?;
    let age = value["last_valid_age_seconds"].as_i64().unwrap_or(i64::MAX);
    if value["state"].as_str() != Some("authenticated") || !(0..=35).contains(&age)
        || value["wire_version"].as_i64() != Some(4)
        || value["config_schema"].as_i64() != Some(3) {
        return Err(failure("Peer is not recently authenticated; refusing to tune an unverified path."));
    }
    Ok(())
}

fn tunnel_samples() -> Option<Samples> {
    let value = fresh_status(PERF_STATUS, 15)?;
    parse_tunnel_samples(&value)
}

fn parse_tunnel_samples(value: &Value) -> Option<Samples> {
    // At least eight actual Pongs in the last two minutes, not merely eight
    // since process startup. Ignore stale smoothed history entirely.
    let count = usize::try_from(value["recent_rtt_samples"].as_u64()?).ok()?;
    let age = value["last_rtt_sample_age_seconds"].as_i64()?;
    if count < 8 || !(0..=35).contains(&age) { return None; }
    let sample = Samples {
        rtt_ms: value["recent_rtt_ms"].as_f64()?,
        jitter_ms: value["recent_jitter_ms"].as_f64()?,
        loss: value["probe_loss_estimate"].as_f64()?,
        count,
    };
    if !sample.rtt_ms.is_finite() || sample.rtt_ms <= 0.0 || sample.rtt_ms >= 60000.0
        || !sample.jitter_ms.is_finite() || sample.jitter_ms < 0.0
        || !sample.loss.is_finite() || !(0.0..=1.0).contains(&sample.loss) {
        return None;
    }
    Some(sample)
}

fn calculate_tcp(s: Samples) -> Option<TcpPlan> {
    if !s.rtt_ms.is_finite() || s.rtt_ms <= 0.0 || s.rtt_ms > 10000.0
        || !s.jitter_ms.is_finite() || s.jitter_ms < 0.0 || s.jitter_ms > 10000.0
        || !s.loss.is_finite() || !(0.0..0.5).contains(&s.loss)
        || s.count < 3 { return None; }
    // High baseline RTT alone does not justify shrinking the TCP window:
    // long-haul paths often have high bandwidth-delay products.
    let stressed = s.loss >= 0.15
        || (s.jitter_ms >= 80.0 && s.jitter_ms >= s.rtt_ms*0.5);
    let moderate = s.loss >= 0.04
        || (s.jitter_ms >= 30.0 && s.jitter_ms >= s.rtt_ms*0.25);
    let (profile, buffer_bytes, window) = if stressed {
        ("conservative", 256*1024, 4096)
    } else if moderate {
        ("balanced", 512*1024, 8192)
    } else {
        ("responsive", 1024*1024, 20000)
    };
    // Ordinary ICMP packet-size probes are NOT a bandwidth or path-MTU test;
    // never adjust TCP memory/window sizes from them.
    let multiplier = if s.loss >= 0.04 { 1.3 } else { 1.0 };
    let resend_ms = ((s.rtt_ms + 4.0*s.jitter_ms + 80.0)*multiplier)
        .round().clamp(350.0, 2400.0) as u64;
    let timeout_secs = if stressed { 120 } else if moderate || s.rtt_ms >= 350.0 { 90 } else { 60 };
    Some(TcpPlan { profile, buffer_bytes, window, resend_ms, timeout_secs })
}

#[derive(Debug, PartialEq)]
struct UdpPlan {
    profile: &'static str,
    socket_buffer_bytes: u64,
    timeout_secs: u64,
}

// UDP packets have no TCP frame window or RTO. Only tune socket queue
// capacity and idle connection lifetime; the kernel can cap SO_RCVBUF/SO_SNDBUF.
// This cannot repair upstream packet loss, change PMTU, or guarantee throughput.
fn calculate_udp(s: Samples) -> Option<UdpPlan> {
    if !s.rtt_ms.is_finite() || !(0.0..=10000.0).contains(&s.rtt_ms)
        || s.rtt_ms == 0.0
        || !s.jitter_ms.is_finite() || !(0.0..=10000.0).contains(&s.jitter_ms)
        || !s.loss.is_finite() || !(0.0..0.5).contains(&s.loss)
        || s.count < 3 { return None; }
    let stressed = s.loss >= 0.15
        || (s.jitter_ms >= 80.0 && s.jitter_ms >= s.rtt_ms*0.5);
    let moderate = s.loss >= 0.04
        || (s.jitter_ms >= 30.0 && s.jitter_ms >= s.rtt_ms*0.25);
    let (profile, socket_buffer_bytes, timeout_secs) = if stressed {
        ("loss-tolerant", 1024*1024, 120)
    } else if moderate {
        ("balanced", 512*1024, 90)
    } else {
        // A larger local socket queue is useful for brief UDP bursts, but
        // should remain small on consistently responsive links.
        ("low-latency", 256*1024, if s.rtt_ms >= 350.0 { 90 } else { 60 })
    };
    Some(UdpPlan { profile, socket_buffer_bytes, timeout_secs })
}

fn service_main_pid() -> Option<u32> {
    let output=Command::new("systemctl")
        .args(["show", "pingtunnel.service", "--property=MainPID", "--value"])
        .output().ok()?;
    if !output.status.success() { return None; }
    let pid=String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().ok()?;
    (pid>0).then_some(pid)
}

fn authenticated_status(state: &Value) -> bool {
    state["state"].as_str()==Some("authenticated")
        && state["region"].as_str()==Some("iran")
        && state["wire_version"].as_i64()==Some(4)
        && state["config_schema"].as_i64()==Some(3)
        && state["last_valid_age_seconds"].as_i64().is_some_and(|age| (0..=20).contains(&age))
}

fn core_restarted_since(started: SystemTime, previous_pid: Option<u32>) -> bool {
    // An active systemd unit and freshly touched file alone do not prove
    // successful re-pairing. Require a new core process and authenticated
    // return traffic within a bounded 45-second window.
    for _ in 0..45 {
        thread::sleep(Duration::from_secs(1));
        let live = Command::new("systemctl")
            .args(["is-active", "--quiet", "pingtunnel.service"])
            .status().is_ok_and(|status| status.success());
        let pid=service_main_pid();
        let new_process=pid.is_some() && pid!=previous_pid;
        let fresh=fs::metadata(SECURITY_STATUS).ok()
            .and_then(|m| m.modified().ok())
            .is_some_and(|t| t.duration_since(started).is_ok());
        if live && new_process && fresh &&
            fresh_status(SECURITY_STATUS, 5).as_ref().is_some_and(authenticated_status) {
            return true;
        }
    }
    false
}

// probe_loss_estimate is a PING/PONG timeout EWMA, not application loss.
// This conservative gate prevents changes when the path is already degraded.
fn safe_to_apply(s: Samples) -> bool {
    s.count >= 8 && s.rtt_ms.is_finite() && s.rtt_ms > 0.0 && s.rtt_ms <= 800.0
        && s.jitter_ms.is_finite() && s.jitter_ms >= 0.0 && s.jitter_ms <= 150.0
        && s.loss.is_finite() && (0.0..=0.10).contains(&s.loss)
}

pub(crate) fn run(apply: bool) -> Result<()> {
    root_required()?;
    let original = load_config()?;
    if get_string(&original, "region") != Some("iran") {
        println!("Auto Tune is Iran-side only. This foreign relay is unchanged (no probes, writes or restarts).");
        return Ok(());
    }
    let transport = get_string(&original, "transport").unwrap();
    require_authenticated_path()?;
    let peer = get_string(&original, "peer_ip").unwrap();
    println!("Auto Tune: measuring authenticated tunnel RTT and IPv4 echo replies to {peer}...");
    let normal_ping = probe(peer, 56, 8);
    let large_ping = probe(peer, 1180, 5);
    // Read authenticated QoS status AFTER diagnostic probes so the decision
    // uses the newest available core samples, not a snapshot from ~10s ago.
    let baseline = tunnel_samples();
    // Raw ICMP echoes may be filtered or independently rate-limited, and
    // neither proves encrypted-tunnel delivery. They are diagnostic only.
    let quality = baseline.ok_or_else(|| failure(
        "Insufficient authenticated RTT samples (need 8 within 120s; last within 35s); no settings changed."))?;
    if let Some(echo)=normal_ping {
        println!("Ordinary echo diagnostic: RTT {:.1} ms, loss {:.1}% (not used for tuning).",
            echo.rtt_ms,echo.loss*100.0);
    } else {
        println!("Ordinary echo diagnostic unavailable (does not penalize encrypted tunnel).");
    }
    // When every ordinary echo probe is filtered, lack of a large-packet
    // response says nothing about the encrypted tunnel's packet-size limit.
    let large_ok = if normal_ping.is_some() {
        Some(large_ping.is_some_and(|value| value.loss <= 0.2))
    } else { None };
    println!("RTT {:.1} ms | jitter {:.1} ms | probe-loss EWMA score {:.1}% (not UDP loss) | large-echo {}",
        quality.rtt_ms, quality.jitter_ms, quality.loss*100.0,
        match large_ok { Some(true) => "passed", Some(false) => "not confirmed", None => "not tested" });

    // Restarting the Go core interrupts live QUIC/VPN sessions.
    // Only an explicit --apply may write config or restart the service.
    if apply && !safe_to_apply(quality) {
        return Err(failure("Path too degraded or unstable for safe Auto Tune; no changes or restarts."));
    }
    let mut updated = original.clone();
    if transport == "tcp" {
        let Some(plan) = calculate_tcp(quality) else {
            if !apply { println!("No safe TCP plan for these measurements; no changes made."); return Ok(()); }
            return Err(failure("Unreliable network measurements; no TCP settings changed."));
        };
        println!("TCP profile: {} | buffer {} KiB | window {} | resend {} ms | timeout {} s",
            plan.profile, plan.buffer_bytes/1024, plan.window, plan.resend_ms, plan.timeout_secs);
        updated["tcp_bs"] = json!(plan.buffer_bytes);
        updated["tcp_mw"] = json!(plan.window);
        updated["tcp_rst"] = json!(plan.resend_ms);
        updated["timeout"] = json!(plan.timeout_secs);
    } else {
        let Some(plan) = calculate_udp(quality) else {
            if !apply { println!("No safe UDP plan for these measurements; no changes made."); return Ok(()); }
            return Err(failure("Unreliable network measurements; no UDP settings changed."));
        };
        println!("UDP profile: {} | socket buffer {} KiB | idle timeout {} s",
            plan.profile, plan.socket_buffer_bytes/1024, plan.timeout_secs);
        println!("UDP socket queue preference is sent to the foreign peer over authenticated DATA frames.");
        println!("No UDP datagram size, MTU, target port or peer identity changes.");
        updated["udp_buf"] = json!(plan.socket_buffer_bytes);
        updated["timeout"] = json!(plan.timeout_secs);
    }
    if updated == original {
        println!("Already using these values; no restart required.");
        return Ok(());
    }
    if !apply {
        println!("PREVIEW ONLY: no configuration writes, peer changes or service restarts.");
        println!("To apply during a maintenance window (disconnects live sessions): sudo pingtunnel auto-tune --apply");
        return Ok(());
    }
    println!("Applying explicit --apply request; active VPN sessions will be interrupted by a core restart.");
    // Stop if the authenticated path disappeared while the active probes ran.
    require_authenticated_path()?;
    let previous_bytes = fs::read(CONFIG)?;
    atomic_save(Path::new(BACKUP), &previous_bytes, 0o600)?;
    store_config(&updated)?;
    let previous_pid = service_main_pid();
    let started = SystemTime::now();
    let applied = apply_config();
    if applied.is_ok() && core_restarted_since(started, previous_pid) {
        println!("Saved and restarted. Previous private config: {BACKUP}");
        println!("Authenticated Go heartbeat restored. This does NOT prove end-to-end VPN/UDP delivery; verify application traffic.");
        if transport == "tcp" {
            println!("The Go adaptive controller will continue adjusting new TCP sessions.");
        } else {
            println!("UDP socket buffers are applied locally and on new compatible foreign UDP associations (subject to OS limits).");
        }
        return Ok(());
    }
    // Do not leave a broken service or changed secrets/ports behind on failure.
    store_config(&original)?;
    let restored = apply_config();
    match restored {
        Ok(()) => Err(failure(format!("Auto Tune service check failed ({}); previous configuration restored.",
            applied.err().map(|e| e.to_string()).unwrap_or_else(|| "no authenticated heartbeat from the restarted Go core".into())))),
        Err(err) => Err(failure(format!("Auto Tune failed AND rollback restart failed: {err}. Previous JSON restored; inspect systemd immediately."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_ping_replies_and_packet_loss() {
        assert_eq!(reply_rtt("64 bytes from 1.2.3.4: seq=1 ttl=45 time=12.5 ms"), Some(12.5));
        assert_eq!(reply_rtt("64 bytes from x: time<1 ms"), Some(1.0));
        assert_eq!(reply_rtt("100% packet loss"), None);
        let result = summarize(&[12.0, 16.0, 14.0], 5).unwrap();
        assert!((result.loss - 0.4).abs() < 0.0001);
        assert!((result.jitter_ms - 3.0).abs() < 0.0001);
    }
    #[test]
    fn choose_bounded_conservative_profiles() {
        let good = Samples { rtt_ms: 40.0, jitter_ms: 5.0, loss: 0.0, count: 8 };
        let fast = calculate_tcp(good).unwrap();
        assert_eq!(fast.profile, "responsive");
        assert_eq!(fast.window, 20000);
        // A stable long-distance link should not lose its send window.
        let distant = Samples { rtt_ms: 500.0, jitter_ms: 12.0, loss: 0.0, count: 10 };
        let distant_plan = calculate_tcp(distant).unwrap();
        assert_eq!(distant_plan.window, 20000);
        assert_eq!(distant_plan.timeout_secs, 90);
        assert_eq!(calculate_tcp(good).unwrap().buffer_bytes, 1024*1024);
        let degraded = calculate_tcp(Samples { rtt_ms: 650.0, jitter_ms: 130.0, loss: 0.2, count: 8 }).unwrap();
        assert_eq!(degraded.profile, "conservative");
        assert!(degraded.resend_ms <= 2400);
        assert_eq!(degraded.timeout_secs, 120);
    }
    #[test]
    fn udp_plan_is_bounded_and_not_tcp_shaped() {
        let stable = Samples { rtt_ms: 35.0, jitter_ms: 2.0, loss: 0.0, count: 12 };
        let plan = calculate_udp(stable).unwrap();
        assert_eq!(plan.profile,"low-latency");
        assert_eq!(plan.socket_buffer_bytes, 262144);
        assert_eq!(plan.timeout_secs, 60);
        let high_rtt = Samples { rtt_ms: 520.0, jitter_ms: 4.0, loss: 0.0, count: 12 };
        assert_eq!(calculate_udp(high_rtt).unwrap().timeout_secs, 90);
        let moderate = Samples { rtt_ms: 120.0, jitter_ms: 15.0, loss: 0.06, count: 12 };
        assert_eq!(calculate_udp(moderate).unwrap().socket_buffer_bytes, 524288);
        let poor = Samples { rtt_ms: 400.0, jitter_ms: 140.0, loss: 0.18, count: 12 };
        let poor_plan = calculate_udp(poor).unwrap();
        assert_eq!(poor_plan.socket_buffer_bytes, 1048576);
        assert_eq!(poor_plan.timeout_secs, 120);
        assert!(calculate_udp(Samples { loss: 0.75, ..stable }).is_none());
        assert!(calculate_udp(Samples { jitter_ms: f64::NAN, ..stable }).is_none());
        assert!(calculate_udp(Samples { count: 2, ..stable }).is_none());
    }
    #[test]
    fn applying_requires_stable_authenticated_samples() {
        let stable = Samples { rtt_ms: 45.0, jitter_ms: 8.0, loss: 0.02, count: 12 };
        assert!(safe_to_apply(stable));
        assert!(!safe_to_apply(Samples { count: 7, ..stable }));
        assert!(!safe_to_apply(Samples { loss: 0.65, ..stable }));
        assert!(!safe_to_apply(Samples { rtt_ms: 2500.0, ..stable }));
        assert!(!safe_to_apply(Samples { jitter_ms: 300.0, ..stable }));
    }
    #[test]
    fn refuses_stale_or_insufficient_authenticated_rtt_samples() {
        let mut status=json!({
            "recent_rtt_samples":12, "recent_rtt_ms":84.0, "recent_jitter_ms":11.0,
            "probe_loss_estimate":0.03, "last_rtt_sample_age_seconds":2
        });
        assert!(parse_tunnel_samples(&status).is_some());
        status["last_rtt_sample_age_seconds"]=json!(50);
        assert!(parse_tunnel_samples(&status).is_none());
        status["last_rtt_sample_age_seconds"]=json!(-1);
        assert!(parse_tunnel_samples(&status).is_none());
        status["last_rtt_sample_age_seconds"]=json!(4);
        status["recent_rtt_samples"]=json!(3);
        assert!(parse_tunnel_samples(&status).is_none());
        status["recent_rtt_samples"]=json!(12);
        status.as_object_mut().unwrap().remove("last_rtt_sample_age_seconds");
        assert!(parse_tunnel_samples(&status).is_none());
    }
    #[test]
    fn reauthentication_requires_matching_secure_peer_state() {
        let mut valid=json!({
            "state":"authenticated", "region":"iran", "wire_version":4,
            "config_schema":3, "last_valid_age_seconds":3
        });
        assert!(authenticated_status(&valid));
        valid["state"]=json!("negotiating");
        assert!(!authenticated_status(&valid));
        valid["state"]=json!("authenticated");
        valid["last_valid_age_seconds"]=json!(50);
        assert!(!authenticated_status(&valid));
        valid["last_valid_age_seconds"]=json!(0);
        valid["wire_version"]=json!(3);
        assert!(!authenticated_status(&valid));
    }
    #[test]
    fn bad_or_insufficient_samples_never_tune() {
        assert!(calculate_tcp(Samples { rtt_ms: f64::NAN, jitter_ms: 1.0, loss: 0.0, count: 8 }).is_none());
        assert!(calculate_tcp(Samples { rtt_ms: 100.0, jitter_ms: 10.0, loss: 0.7, count: 8 }).is_none());
        assert!(calculate_tcp(Samples { rtt_ms: 100.0, jitter_ms: 10.0, loss: 0.0, count: 1 }).is_none());
    }
}
