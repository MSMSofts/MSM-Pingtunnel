//! UDP high availability: each source SocketAddr owns one independent UDP flow.
//! Established flows stay on their Go endpoint on preference changes; if the
//! endpoint becomes unhealthy, later datagrams can move to a healthy endpoint.
//! UDP has no transferable transport session state, so packet loss is possible.

use super::{RouterState, Settings, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

struct FlowEntry {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

fn active_route(state: &RouterState) -> Option<usize> {
    state
        .active
        .filter(|&idx| state.health.get(idx).map(|h| h.good).unwrap_or(false))
        .or_else(|| state.health.iter().position(|h| h.good))
}

fn fallback_route(state: &RouterState, pinned: usize) -> Option<usize> {
    if state.health.get(pinned).map(|h| h.good).unwrap_or(false) {
        Some(pinned)
    } else {
        active_route(state)
    }
}

async fn connect_backend(port: u16) -> std::io::Result<UdpSocket> {
    // One connected UDP socket per client peer. Go uses its UDP remote address
    // as an independent flow identity, preventing reply/session cross-talk.
    let backend = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    backend.connect((Ipv4Addr::LOCALHOST, port)).await?;
    Ok(backend)
}

async fn handle_flow(
    peer: SocketAddr,
    original_route: usize,
    settings: Settings,
    state: Arc<Mutex<RouterState>>,
    public: Arc<UdpSocket>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
) {
    let mut pinned = original_route;
    let mut backend = match connect_backend(settings.routes[pinned].data_port).await {
        Ok(sock) => sock,
        Err(error) => {
            eprintln!("HA UDP: failed to create backend for peer {peer}: {error}");
            return;
        }
    };
    let mut buffer = vec![0_u8; 65535];
    let mut last_activity = Instant::now();
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            packet = incoming.recv() => match packet {
                Some(datagram) => {
                    // Do not reshuffle a healthy existing flow just because a
                    // different endpoint becomes the preferred route.
                    last_activity = Instant::now();
                    if let Err(error) = backend.send(&datagram).await {
                        eprintln!("HA UDP: backend send to {} failed: {error}", settings.routes[pinned].name);
                    }
                }
                None => break,
            },
            result = backend.recv(&mut buffer) => match result {
                Ok(received) => {
                    last_activity = Instant::now();
                    if let Err(error) = public.send_to(&buffer[..received], peer).await {
                        eprintln!("HA UDP: response to {peer} failed: {error}");
                    }
                }
                Err(error) => {
                    eprintln!("HA UDP: backend reply error for {peer}: {error}");
                    // Wait for the health checker to mark the path unhealthy.
                    // Remaining pinned avoids churning on a transient socket error.
                }
            },
            _ = ticker.tick() => {
                if last_activity.elapsed() >= Duration::from_secs(settings.udp_idle_seconds) {
                    break;
                }
                let selected = {
                    let guard = state.lock().unwrap();
                    fallback_route(&guard, pinned)
                };
                if let Some(other) = selected {
                    if other != pinned {
                        match connect_backend(settings.routes[other].data_port).await {
                            Ok(socket) => {
                                backend = socket;
                                pinned = other;
                                eprintln!("HA UDP: moved peer {peer} to healthy endpoint {}", settings.routes[pinned].name);
                            }
                            Err(error) => {
                                eprintln!("HA UDP: cannot migrate peer {peer}: {error}");
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(super) async fn serve(settings: Settings, state: Arc<Mutex<RouterState>>) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(settings.listen).await?);
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel::<(SocketAddr, u64)>();
    let mut sessions: HashMap<SocketAddr, FlowEntry> = HashMap::new();
    let mut next_generation: u64 = 0;
    let mut datagram = vec![0u8; 65535];
    eprintln!(
        "HA UDP: listening on {} with {} warm Go UDP endpoints; {}s idle expiration",
        settings.listen, settings.routes.len(), settings.udp_idle_seconds
    );

    loop {
        tokio::select! {
            received = socket.recv_from(&mut datagram) => {
                let (size, peer) = received?;
                if sessions.get(&peer).map(|e| e.sender.is_closed()).unwrap_or(false) {
                    sessions.remove(&peer);
                }
                if !sessions.contains_key(&peer) {
                    if sessions.len() >= settings.max_connections {
                        // Bound memory consumption on public UDP listeners.
                        continue;
                    }
                    let chosen = {
                        let guard = state.lock().unwrap();
                        active_route(&guard)
                    };
                    let Some(route_index) = chosen else {
                        // No healthy Pingtunnel route is currently available.
                        continue;
                    };
                    next_generation = next_generation.wrapping_add(1);
                    let generation = next_generation;
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                    sessions.insert(peer, FlowEntry { generation, sender: tx });
                    let settings = settings.clone();
                    let state = state.clone();
                    let socket = socket.clone();
                    let ended = cleanup_tx.clone();
                    tokio::spawn(async move {
                        handle_flow(peer, route_index, settings, state, socket, rx).await;
                        let _ = ended.send((peer, generation));
                    });
                }
                if let Some(entry) = sessions.get(&peer) {
                    // Nonblocking admission: overflowing clients drop datagrams,
                    // never block other peers or allocate an unbounded queue.
                    let _ = entry.sender.try_send(datagram[..size].to_vec());
                }
            },
            Some((peer, generation)) = cleanup_rx.recv() => {
                if sessions.get(&peer).map(|e| e.generation) == Some(generation) {
                    sessions.remove(&peer);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::time::{sleep, timeout};

    fn settings() -> Settings {
        super::super::parse(&json!({
            "type":"client", "tcp":0, "l_port":5353, "key":"12345",
            "target":"127.0.0.1:5353",
            "ha":{"enabled":true,"endpoints":[
                {"name":"a","server":"203.0.113.1"},
                {"name":"b","server":"198.51.100.2"}],
                "udp_idle_seconds":10}
        })).unwrap()
    }

    #[test]
    fn preserves_a_healthy_udp_flow_when_preference_switches() {
        let mut state = RouterState {
            active: Some(1), switches: 0, last_switch: Instant::now(),
            health: vec![super::super::Health::default(), super::super::Health::default()],
        };
        state.health[0].good = true;
        state.health[1].good = true;
        assert_eq!(fallback_route(&state, 0), Some(0));
        state.health[0].good = false;
        assert_eq!(fallback_route(&state, 0), Some(1));
    }

    #[tokio::test]
    async fn udp_flows_stay_pinned_until_original_path_is_unhealthy() {
        // Two mock Go UDP ports mark replies with their endpoint identity.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port_a = a.local_addr().unwrap().port();
        let port_b = b.local_addr().unwrap().port();
        let echo_a = tokio::spawn(async move {
            let mut bytes = [0_u8; 128];
            loop {
                let (n, peer) = a.recv_from(&mut bytes).await.unwrap();
                let mut answer = b"A:".to_vec();
                answer.extend_from_slice(&bytes[..n]);
                a.send_to(&answer, peer).await.unwrap();
            }
        });
        let echo_b = tokio::spawn(async move {
            let mut bytes = [0_u8; 128];
            loop {
                let (n, peer) = b.recv_from(&mut bytes).await.unwrap();
                let mut answer = b"B:".to_vec();
                answer.extend_from_slice(&bytes[..n]);
                b.send_to(&answer, peer).await.unwrap();
            }
        });
        let mut cfg = settings();
        cfg.routes[0].data_port = port_a;
        cfg.routes[1].data_port = port_b;
        cfg.listen = "127.0.0.1:0".parse().unwrap();

        // Bind a stable UDP public port before the proxy starts; use an
        // independently reserved local port for this test.
        let reserve = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let public_port = reserve.local_addr().unwrap().port();
        drop(reserve);
        cfg.listen.set_port(public_port);

        let state = Arc::new(Mutex::new(RouterState {
            active: Some(0), switches: 0, last_switch: Instant::now(),
            health: vec![
                super::super::Health {good:true, ..Default::default()},
                super::super::Health {good:true, ..Default::default()}
            ],
        }));
        let public = cfg.listen;
        let background_state = state.clone();
        let ctrl = tokio::spawn(async move { serve(cfg, background_state).await.expect("UDP HA listener failed"); });
        sleep(Duration::from_millis(30)).await;
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        async fn send(socket: &UdpSocket, value: &[u8], public: SocketAddr) -> String {
            socket.send_to(value, public).await.unwrap();
            let mut buf = [0u8; 128];
            let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        }
        assert_eq!(send(&first, b"one", public).await, "A:one");
        {
            state.lock().unwrap().active = Some(1);
        }
        // Existing peer stays on A while A is healthy.
        assert_eq!(send(&first, b"two", public).await, "A:two");
        // New peer switches to B immediately.
        assert_eq!(send(&second, b"three", public).await, "B:three");
        state.lock().unwrap().health[0].good = false;
        // The UDP worker sees the failure and rebinds to B.
        sleep(Duration::from_millis(1150)).await;
        assert_eq!(send(&first, b"four", public).await, "B:four");
        ctrl.abort();
        echo_a.abort();
        echo_b.abort();
    }

    #[test]
    fn udp_capacity_and_idle_time_are_validated() {
        let mut cfg = json!({
            "type":"client", "tcp":0, "l_port":5353, "key":"12345",
            "target":"127.0.0.1:5353",
            "ha":{"enabled":true,"endpoints":[
                {"name":"a","server":"203.0.113.1"},
                {"name":"b","server":"198.51.100.2"}],
                "udp_idle_seconds":0}
        });
        assert!(super::super::parse(&cfg).is_err());
        cfg["ha"]["udp_idle_seconds"] = json!(120);
        assert!(super::super::parse(&cfg).is_ok());
    }
}
