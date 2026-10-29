//! Pingtunnel terminal UI.
//! Use CRLF while crossterm has disabled terminal output processing in raw mode.
//! Fixed-width, vertically ordered actions; no arbitrary terminal-width wraps.
use crate::resource_monitor::{ResourceMonitor, Resources};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::env;
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};
use std::time::{Duration, Instant};

pub(crate) struct MenuView<'a> {
    pub version: &'a str,
    pub region: &'a str,
    pub peer: &'a str,
    pub transport: &'a str,
    pub port: Option<u16>,
    pub service: &'a str,
    pub configured: bool,
    pub resources: Resources,
}

pub(crate) fn supports_color() -> bool {
    io::stdout().is_terminal()
        && env::var_os("NO_COLOR").is_none()
        && env::var("TERM").map(|v| v != "dumb" && !v.is_empty()).unwrap_or(false)
}

pub(crate) fn supports_unicode() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|name| env::var(name).ok())
        .find(|locale| !locale.is_empty())
        .map(|locale| {
            let locale = locale.to_ascii_lowercase();
            locale.contains("utf-8") || locale.contains("utf8")
        })
        .unwrap_or(false)
}

fn paint(value: &str, color: &str, enabled: bool) -> String {
    if enabled { format!("\x1b[{color}m{value}\x1b[0m") } else { value.into() }
}

/// Limit visible ASCII text to a terminal-safe width before adding ANSI styles.
fn short(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn rule(out: &mut String, width: usize, unicode: bool, color: bool) {
    let line = if unicode { "─" } else { "-" };
    let _ = writeln!(out, "{}", paint(&line.repeat(width), "2;36", color));
}

fn heading(out: &mut String, caption: &str, width: usize, unicode: bool, color: bool) {
    let symbol = if unicode { "◆" } else { ">" };
    let _ = writeln!(out, "{}", paint(&format!("{symbol}  {caption}"), "1;36", color));
    let line = if unicode { "─" } else { "-" };
    let _ = writeln!(out, "{}", paint(&line.repeat(width), "2", color));
}

const SERVICE: [(u8, &str, &str); 5] = [
    (1, "Status", "View service details"),
    (2, "Start", "Start the tunnel"),
    (3, "Stop", "Stop the tunnel"),
    (4, "Restart", "Restart the tunnel"),
    (5, "Logs", "Last 100 journal entries"),
];
const CONFIG: [(u8, &str, &str); 2] = [
    (6, "Setup Wizard", "Configure this VPS"),
    (7, "Pairing key", "Show secret (root only)"),
];
const DIAGNOSTIC: [(u8, &str, &str); 2] = [
    (8, "Performance", "RTT, jitter and loss"),
    (9, "Validate", "Check configuration"),
];
const MAINTENANCE: [(u8, &str, &str); 3] = [
    (10, "Update", "Upgrade + restart tunnel"),
    (11, "Uninstall", "Remove program"),
    (12, "Exit", "Close menu"),
];
const SECURITY: [(u8, &str, &str); 3] = [
    (13, "Security", "Replay and recovery"),
    (14, "Health", "Core heartbeat"),
    (15, "Auto Tune", "Test path; tune TCP/UDP"),
];

fn options(out: &mut String, section: &str, entries: &[(u8, &str, &str)],
           width: usize, unicode: bool, color: bool, compact: bool) {
    if !compact { heading(out, section, width, unicode, color); }
    for (number, label, explanation) in entries {
        let left = format!("  {number:>2}) {label:<19}");
        if compact || width < 56 {
            let _ = writeln!(out, "{}", paint(&format!("  {number:>2}) {label}"), "1;37", color));
        } else {
            let desc_width = width.saturating_sub(left.len()+3);
            let _ = writeln!(out, "{}{}", paint(&left, "1;37", color),
                paint(&short(explanation,desc_width), "2", color));
        }
    }
}

/// View is deliberately single-column. Menu choices are 1..15 from TOP to
/// BOTTOM, so visual scanning and terminal keyboard input agree.
pub(crate) fn render_sized(view: &MenuView<'_>, color: bool, unicode: bool,
                           columns: u16, rows: u16) -> String {
    let mut out = String::new();
    // Keep a margin for terminals that auto-wrap at their last column.
    let width = usize::from(columns).saturating_sub(3).min(65).max(16);
    let compact = rows < 40;
    let line = if unicode { "━" } else { "=" };
    let _ = writeln!(out, "{}", paint(&line.repeat(width), "1;36", color));
    let _ = writeln!(out, "{}", paint("  PINGTUNNEL  /  CONTROL CENTER", "1;36", color));
    let version = format!("  v{}   |   Encrypted ICMP   |   Wire v4", view.version);
    let _ = writeln!(out, "{}", paint(&short(&version, width), "2", color));
    rule(&mut out,width,unicode,color);

    if !compact {
        heading(&mut out,"LIVE TUNNEL STATUS",width,unicode,color);
    }
    let location = match view.region {
        "iran"=>"Iran (ingress)",
        "foreign"=>"Foreign (service)",
        _=>"Not configured",
    };
    let transport = if view.configured {view.transport.to_ascii_uppercase()} else {"-".into()};
    let port = view.port.map(|v|v.to_string()).unwrap_or_else(||"-".into());
    let _ = writeln!(out,"  {:<12} {}", "Location",location);
    let _ = writeln!(out,"  {:<12} {}", "Peer IPv4",short(if view.configured{view.peer}else{"-"},width.saturating_sub(16)));
    let _ = writeln!(out,"  {:<12} {} / {}", "Transport",transport,port);
    let state_color=if view.service=="active"{"1;32"} else if view.service=="failed"{"1;31"}else{"1;33"};
    let _ = writeln!(out,"  {:<12} {}", "Service",paint(view.service,state_color,color));

    let missing=if unicode{"—"}else{"-"};
    let cpu=view.resources.cpu_percent.map(|v|format!("{v:.1}%")).unwrap_or_else(||missing.into());
    let avg_cpu=view.resources.cpu_average.map(|v|format!("{v:.1}%")).unwrap_or_else(||missing.into());
    let ram=view.resources.ram_mib.map(|v|format!("{v:.1} MiB")).unwrap_or_else(||missing.into());
    let avg_ram=view.resources.ram_average.map(|v|format!("{v:.1} MiB")).unwrap_or_else(||missing.into());
    // No duplicated layout padding inside ANSI escapes: all metrics aligned.
    let _ = writeln!(out,"  {:<12} {}",
        "CPU (10s)",paint(&format!("{cpu:<13} avg 60s {avg_cpu}"),"1;33",color));
    let _ = writeln!(out,"  {:<12} {}",
        "RAM (RSS)",paint(&format!("{ram:<13} avg 60s {avg_ram}"),"1;35",color));
    if !view.configured {
        let _=writeln!(out,"{}",paint("  Not configured: choose 6) Setup Wizard", "1;33",color));
    }
    if !compact {
        let _ = writeln!(out,"{}",paint("  Auto refresh: 10s  |  CPU 100% = one vCPU","2",color));
    }

    options(&mut out,"SERVICE CONTROLS",&SERVICE,width,unicode,color,compact);
    options(&mut out,"SETUP & CONFIGURATION",&CONFIG,width,unicode,color,compact);
    options(&mut out,"DIAGNOSTICS",&DIAGNOSTIC,width,unicode,color,compact);
    options(&mut out,"MAINTENANCE",&MAINTENANCE,width,unicode,color,compact);
    options(&mut out,"SECURITY, HEALTH & TUNING",&SECURITY,width,unicode,color,compact);
    out
}

pub(crate) fn render(view:&MenuView<'_>,color:bool,unicode:bool)->String {
    render_sized(view,color,unicode,80,40)
}

pub(crate) fn interactive_available()->bool{
    io::stdin().is_terminal() && io::stdout().is_terminal()
        && env::var("TERM").map(|v|v!="dumb"&&!v.is_empty()).unwrap_or(false)
        && terminal::size().map(|(cols,rows)|cols>=47 && rows>=27).unwrap_or(false)
}

/// Raw mode disables ONLCR on Linux. Newlines MUST be CRLF or the cursor will
/// keep its previous column and create the diagonal "staircase" shown in the
/// issue screenshot. Applies to the whole frame including prompt/help.
fn raw_frame(view: &str, hint: &str, typed: &str) -> String {
    let mut screen = String::with_capacity(view.len()+hint.len()+typed.len()+32);
    screen.push_str(view);
    screen.push_str(hint);
    screen.push_str(typed);
    screen.replace('\n',"\r\n")
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _=terminal::disable_raw_mode();
        let mut output=io::stdout();
        let _=execute!(output,LeaveAlternateScreen,cursor::Show);
    }
}

/// Poll input without consuming partially typed numbers during 10s redraw.
/// Alternate screen and raw mode are restored before any shell/setup command.
pub(crate) fn choose<F>(monitor:&mut ResourceMonitor, mut draw:F, default:&str)->io::Result<String>
where F:FnMut(Resources,u16,u16)->String {
    terminal::enable_raw_mode()?;
    let mut output=io::stdout();
    if let Err(e)=execute!(output,EnterAlternateScreen,cursor::Hide){
        let _=terminal::disable_raw_mode();
        return Err(e);
    }
    let _guard=TerminalGuard;
    let mut entered=String::new();
    let mut refreshed=Instant::now();
    loop {
        let (cols,rows)=terminal::size().unwrap_or((80,40));
        let display=draw(monitor.current(),cols,rows);
        let compact=rows<40;
        let hint=if compact{"  Enter: select  |  Esc: exit\n"}
            else{"\n  Enter: confirm   Backspace: edit   Esc/q: exit\n"};
        let prompt=format!("  > {}",if entered.is_empty(){format!("[{default}]")}else{entered.clone()});
        let screen=raw_frame(&display,hint,&prompt);
        execute!(output,cursor::MoveTo(0,0),terminal::Clear(ClearType::All))?;
        output.write_all(screen.as_bytes())?;
        output.flush()?;

        let remaining=Duration::from_secs(10).saturating_sub(refreshed.elapsed());
        if event::poll(remaining)? {
            if let Event::Key(key)=event::read()?{
                if key.kind!=KeyEventKind::Press{continue;}
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>return Ok("12".into()),
                    KeyCode::Char('q'|'Q')|KeyCode::Esc=>return Ok("12".into()),
                    KeyCode::Char(c) if c.is_ascii_digit()&&entered.len()<2=>entered.push(c),
                    KeyCode::Backspace=>{entered.pop();},
                    KeyCode::Enter=>return Ok(if entered.is_empty(){default.into()}else{entered}),
                    _=>{},
                }
            }
        }
        if refreshed.elapsed()>=Duration::from_secs(10) {
            monitor.refresh();
            refreshed=Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture()->MenuView<'static> {
        MenuView{version:"3.2.4",region:"foreign",peer:"203.0.113.10",
            transport:"udp",port:Some(444),service:"active",
            configured:true,resources:Resources{cpu_percent:Some(0.3),cpu_average:Some(0.3),
                ram_mib:Some(13.9),ram_average:Some(13.9),samples:6}}
    }

    #[test]
    fn choices_are_strictly_top_to_bottom_1_to_15() {
        for (cols,rows) in [(80,40),(52,30),(47,27)]{
            let s=render_sized(&fixture(),false,false,cols,rows);
            let choices:Vec<u8>=s.lines().filter_map(|line|{
                let text=line.trim_start();
                let (prefix,_) = text.split_once(')')?;
                prefix.trim().parse::<u8>().ok()
            }).collect();
            assert_eq!(choices,(1..=15).collect::<Vec<u8>>());
            assert!(s.contains("0.3%"));
            assert!(s.contains("13.9 MiB"));
            assert!(!s.contains("\x1b["));
            // The terminal must never wrap a produced line on its last column.
            assert!(s.lines().all(|line|line.chars().count()<usize::from(cols)), "{cols} cols");
        }
    }

    #[test]
    fn raw_mode_entire_frame_uses_crlf_not_bare_lf() {
        let raw=raw_frame("HEADER\nStatus\n","  Enter\n","  > [1]\n");
        assert_eq!(raw,"HEADER\r\nStatus\r\n  Enter\r\n  > [1]\r\n");
        assert!(!raw.replace("\r\n","").contains('\n'));
    }

    #[test]
    fn unicode_and_ascii_are_both_readable() {
        let fancy=render_sized(&fixture(),true,true,80,40);
        assert!(fancy.contains("\x1b[") && fancy.contains("◆"));
        let ascii=render_sized(&fixture(),false,false,80,40);
        assert!(!ascii.contains("◆") && !ascii.contains('—'));
    }

    #[test]
    fn inactive_and_not_configured_do_not_forge_metrics() {
        let mut view=fixture();
        view.configured=false;
        view.region="unknown";
        view.service="inactive";
        view.resources=Resources::default();
        let result=render(&view,false,false);
        assert!(result.contains("Not configured: choose 6)"));
        assert!(result.contains("Service      inactive"));
        assert!(result.contains("avg 60s -"));
        assert!(!result.contains("pair_key"));
    }
}
