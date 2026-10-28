//! One-shot, conservative tuning for the Iran-side TCP forwarding client.
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
struct Plan {
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
    let count = usize::try_from(value["rtt_samples"].as_u64()?).ok()?;
    if count < 8 { return None; }
    let sample = Samples {
        rtt_ms: value["rtt_ms"].as_f64()?,
        jitter_ms: value["jitter_ms"].as_f64()?,
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

fn calculate(s: Samples, large_packets_ok: bool) -> Option<Plan> {
    if !s.rtt_ms.is_finite() || s.rtt_ms <= 0.0 || s.rtt_ms > 10000.0
        || !s.jitter_ms.is_finite() || s.jitter_ms < 0.0 || s.jitter_ms > 10000.0
        || !s.loss.is_finite() || !(0.0..0.5).contains(&s.loss)
        || s.count < 3 { return None; }
    let stressed = s.loss >= 0.15 || s.rtt_ms >= 350.0 || s.jitter_ms >= 110.0;
    let moderate = s.loss >= 0.04 || s.rtt_ms >= 160.0 || s.jitter_ms >= 40.0;
    let (profile, mut buffer_bytes, mut window) = if stressed {
        ("conservative", 256*1024, 2048)
    } else if moderate {
        ("balanced", 512*1024, 4096)
    } else {
        ("responsive", 1024*1024, 12000)
    };
    // ICMP packet-size success is only a rough path-quality signal, NOT
    // a bandwidth measurement or an exact tunnel MTU discovery.
    if !large_packets_ok {
        buffer_bytes = buffer_bytes.min(256*1024);
        window = window.min(4096);
    }
    let multiplier = if s.loss >= 0.04 { 1.3 } else { 1.0 };
    let resend_ms = ((s.rtt_ms + 4.0*s.jitter_ms + 80.0)*multiplier)
        .round().clamp(350.0, 2400.0) as u64;
    let timeout_secs = if stressed { 120 } else if moderate { 90 } else { 60 };
    Some(Plan { profile, buffer_bytes, window, resend_ms, timeout_secs })
}

fn core_restarted_since(started: SystemTime) -> bool {
    for _ in 0..8 {
        thread::sleep(Duration::from_secs(1));
        let live = Command::new("systemctl")
            .args(["is-active", "--quiet", "pingtunnel.service"])
            .status().map(|s| s.success()).unwrap_or(false);
        let heartbeat = fs::metadata(SECURITY_STATUS).ok()
            .and_then(|m| m.modified().ok())
            .map(|t| t.duration_since(started).is_ok()).unwrap_or(false);
        if live && heartbeat { return true; }
    }
    false
}

pub(crate) fn run() -> Result<()> {
    root_required()?;
    let original = load_config()?;
    if get_string(&original, "region") != Some("iran")
        || get_string(&original, "transport") != Some("tcp") {
        return Err(failure("Auto Tune currently applies only to the Iran-side TCP client; UDP/foreign settings are unchanged."));
    }
    require_authenticated_path()?;
    let peer = get_string(&original, "peer_ip").unwrap();
    println!("Auto Tune: measuring authenticated tunnel RTT and IPv4 echo replies to {peer}...");
    let baseline = tunnel_samples();
    let normal_ping = probe(peer, 56, 8);
    let large_ping = probe(peer, 1180, 5);
    let quality = match (baseline, normal_ping) {
        (Some(tunnel), Some(echo)) => Samples {
            rtt_ms: tunnel.rtt_ms,
            jitter_ms: tunnel.jitter_ms,
            loss: tunnel.loss.max(echo.loss),
            count: tunnel.count,
        },
        (Some(tunnel), None) => {
            println!("Standard ICMP echo unavailable; using authenticated tunnel measurements.");
            tunnel
        },
        (None, Some(echo)) => {
            println!("Authenticated RTT history is too short; using ICMP echo measurements.");
            echo
        },
        (None, None) => return Err(failure("Insufficient network samples; no settings were changed.")),
    };
    let large_ok = large_ping.is_some_and(|value| value.loss <= 0.2);
    let plan = calculate(quality, large_ok)
        .ok_or_else(|| failure("Loss, RTT or jitter is too high/invalid to tune safely; no settings changed."))?;
    println!("RTT {:.1} ms | jitter {:.1} ms | loss {:.1}% | large-echo {}",
        quality.rtt_ms, quality.jitter_ms, quality.loss*100.0,
        if large_ok {"passed"} else {"unconfirmed"});
    println!("Profile: {} | TCP buffer {} KiB | window {} | resend {} ms | timeout {} s",
        plan.profile, plan.buffer_bytes/1024, plan.window, plan.resend_ms, plan.timeout_secs);

    let mut updated = original.clone();
    updated["tcp_bs"] = json!(plan.buffer_bytes);
    updated["tcp_mw"] = json!(plan.window);
    updated["tcp_rst"] = json!(plan.resend_ms);
    updated["timeout"] = json!(plan.timeout_secs);
    if updated == original {
        println!("Already using these values; no restart required.");
        return Ok(());
    }
    // Stop if the authenticated path disappeared while the active probes ran.
    require_authenticated_path()?;
    let previous_bytes = fs::read(CONFIG)?;
    atomic_save(Path::new(BACKUP), &previous_bytes, 0o600)?;
    store_config(&updated)?;
    let started = SystemTime::now();
    let applied = apply_config();
    if applied.is_ok() && core_restarted_since(started) {
        println!("Saved and restarted. Previous private config: {BACKUP}");
        println!("The Go adaptive controller will continue adjusting new TCP sessions.");
        return Ok(());
    }
    // Do not leave a broken service or changed secrets/ports behind on failure.
    store_config(&original)?;
    let restored = apply_config();
    match restored {
        Ok(()) => Err(failure(format!("Auto Tune service check failed ({}); previous configuration restored.",
            applied.err().map(|e| e.to_string()).unwrap_or_else(|| "no new Go heartbeat".into())))),
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
        let fast = calculate(good, true).unwrap();
        assert_eq!(fast.profile, "responsive");
        assert_eq!(fast.window, 12000);
        assert_eq!(calculate(good, false).unwrap().buffer_bytes, 256*1024);
        let degraded = calculate(Samples { rtt_ms: 650.0, jitter_ms: 130.0, loss: 0.2, count: 8 }, false).unwrap();
        assert_eq!(degraded.profile, "conservative");
        assert!(degraded.resend_ms <= 2400);
        assert_eq!(degraded.timeout_secs, 120);
    }
    #[test]
    fn bad_or_insufficient_samples_never_tune() {
        assert!(calculate(Samples { rtt_ms: f64::NAN, jitter_ms: 1.0, loss: 0.0, count: 8 }, true).is_none());
        assert!(calculate(Samples { rtt_ms: 100.0, jitter_ms: 10.0, loss: 0.7, count: 8 }, true).is_none());
        assert!(calculate(Samples { rtt_ms: 100.0, jitter_ms: 10.0, loss: 0.0, count: 1 }, true).is_none());
    }
}
