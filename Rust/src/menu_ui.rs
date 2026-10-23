//! Terminal-only presentation of Pingtunnel Manager.
//! No schema, service, port, protocol, or secret-handling changes live here.
use std::fmt::Write as _;
use std::io::{self, IsTerminal};
use std::env;
use std::io::Write as _;
use std::time::{Duration, Instant};
use crossterm::{cursor, event::{self, Event, KeyCode, KeyEventKind, KeyModifiers}, execute, terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen}};
use crate::resource_monitor::{Resources,ResourceMonitor};

const INNER_WIDTH: usize = 66;

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
        && env::var("TERM").map(|term| term != "dumb" && !term.is_empty()).unwrap_or(false)
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

fn colored(value: &str, style: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{style}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

fn frame_line(out: &mut String, text: &str, unicode: bool, color: bool) {
    let length = text.chars().count();
    let padded = format!("{text}{}", " ".repeat(INNER_WIDTH.saturating_sub(length)));
    let (edge, closing) = if unicode { ("│", "│") } else { ("|", "|") };
    let _ = writeln!(out, "{} {} {}", colored(edge, "2;36", color), padded, colored(closing, "2;36", color));
}

fn section(out: &mut String, heading: &str, color: bool, unicode: bool) {
    let rule = if unicode { "─" } else { "-" };
    let _ = writeln!(out);
    let _ = writeln!(out, "  {}", colored(heading, "1;36", color));
    let _ = writeln!(out, "  {}", colored(&rule.repeat(INNER_WIDTH), "2", color));
}

fn option_line(out: &mut String, first: (u8, &str), second: Option<(u8, &str)>, ansi: bool) {
    let format_option = |(number, caption): (u8, &str)| {
        let n = format!("{number:>2})");
        format!("{} {caption}", colored(&n, "1;36", ansi))
    };
    let left_text = format!("{:>2}) {}", first.0, first.1);
    let gap = " ".repeat(33usize.saturating_sub(left_text.len()));
    let first_styled = format_option(first);
    match second {
        Some(item) => {
            let _ = writeln!(out, "  {first_styled}{gap}{}", format_option(item));
        }
        None => {
            let _ = writeln!(out, "  {first_styled}");
        }
    }
}

pub(crate) fn render(view: &MenuView<'_>, color: bool, unicode: bool) -> String {
    let mut out = String::new();
    let (top_left, top_right, bottom_left, bottom_right, horizontal) =
        if unicode { ("┌", "┐", "└", "┘", "─") } else { ("+", "+", "+", "+", "-") };
    let border = horizontal.repeat(INNER_WIDTH + 2);
    let _ = writeln!(
        out,
        "\n{}{}{}",
        colored(top_left, "36", color),
        colored(&border, "36", color),
        colored(top_right, "36", color)
    );
    frame_line(&mut out, "  PINGTUNNEL  /  NETWORK CONTROL CENTER", unicode, color);
    frame_line(
        &mut out,
        &format!("  ENCRYPTED ICMP  /  v{}  /  WIRE 4  /  IRAN <> FOREIGN", view.version),
        unicode, color,
    );
    let _ = writeln!(
        out,
        "{}{}{}",
        colored(bottom_left, "36", color),
        colored(&border, "36", color),
        colored(bottom_right, "36", color)
    );

    section(&mut out, "01  LIVE TUNNEL OVERVIEW", color, unicode);
    let location = match view.region {
        "iran" => "Iran (ingress)",
        "foreign" => "Foreign (service)",
        _ => "Not configured",
    };
    let port = view.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    let transport = if view.configured { view.transport.to_ascii_uppercase() } else { "-".into() };
    let status_style = if view.service == "active" { "1;32" }
        else if view.service == "failed" { "1;31" }
        else { "1;33" };
    let _ = writeln!(out, "  {:<18}: {}", "Location", location);
    let _ = writeln!(out, "  {:<18}: {}", "Peer IPv4", if view.configured { view.peer } else { "-" });
    let _ = writeln!(out, "  {:<18}: {transport} / {port}", "Local transport");
    let _ = writeln!(
        out,
        "  {:<18}: {}",
        "Service status",
        colored(view.service, status_style, color)
    );
    if !view.configured {
        let _ = writeln!(
            out, "  {}",
            colored("No valid configuration: run Setup Wizard (option 6).", "1;33", color)
        );
    }

    let current_cpu=view.resources.cpu_percent
        .map(|v|format!("{v:.1}%")).unwrap_or_else(||"—".into());
    let mean_cpu=view.resources.cpu_average
        .map(|v|format!("{v:.1}%")).unwrap_or_else(||"—".into());
    let current_ram=view.resources.ram_mib
        .map(|v|format!("{v:.1} MiB")).unwrap_or_else(||"—".into());
    let mean_ram=view.resources.ram_average
        .map(|v|format!("{v:.1} MiB")).unwrap_or_else(||"—".into());
    let _=writeln!(out,"  {:<18}: {:<20} {}", "CPU (10s)",colored(&current_cpu,"1;33",color),format!("Avg 60s: {mean_cpu}"));
    let _=writeln!(out,"  {:<18}: {:<20} {}", "RAM (RSS)",colored(&current_ram,"1;35",color),format!("Avg 60s: {mean_ram}"));
    let _=writeln!(out,"  {}",colored("  Sample every 10s | CPU 100% = one vCPU | — = unavailable", "2",color));

    section(&mut out, "02  SERVICE CONTROLS", color, unicode);
    option_line(&mut out, (1, "Status"), Some((2, "Start")), color);
    option_line(&mut out, (3, "Stop"), Some((4, "Restart")), color);
    option_line(&mut out, (5, "View logs"), None, color);

    section(&mut out, "03  SETUP & CONFIGURATION", color, unicode);
    option_line(&mut out, (6, "Setup Wizard"), Some((7, "Show pairing key")), color);

    section(&mut out, "04  DIAGNOSTICS", color, unicode);
    option_line(&mut out, (8, "Adaptive Performance"), Some((9, "Validate config")), color);
    option_line(&mut out, (13, "Security status"), Some((14, "Health check")), color);

    section(&mut out, "05  MAINTENANCE", color, unicode);
    option_line(&mut out, (10, "Update"), Some((11, "Uninstall")), color);
    option_line(&mut out, (12, "Exit"), None, color);
    let _ = writeln!(out);
    out
}


/// Only an attached interactive terminal is redrawn. Pipe/CI operation keeps
/// traditional line-oriented input, with no unexpected control sequences.
pub(crate) fn interactive_available() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
        && env::var("TERM").map(|term|term!="dumb"&&!term.is_empty()).unwrap_or(false)
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _=terminal::disable_raw_mode();
        let mut out=io::stdout();
        let _=execute!(out,LeaveAlternateScreen,cursor::Show);
    }
}

/// Keyboard polling keeps the input buffer intact while the 10s view refreshes.
/// Actions run AFTER leaving raw mode, so the setup wizard and its hidden
/// pairing-key prompt still have normal terminal behavior.
pub(crate) fn choose<F>(monitor:&mut ResourceMonitor, mut draw:F, default:&str)->io::Result<String>
where F:FnMut(Resources)->String
{
    terminal::enable_raw_mode()?;
    let mut out=io::stdout();
    if let Err(err)=execute!(out,EnterAlternateScreen,cursor::Hide) {
        let _=terminal::disable_raw_mode();
        return Err(err);
    }
    let _guard=TerminalGuard;
    let mut entered=String::new();
    let mut last=Instant::now();

    loop{
        let display=draw(monitor.current());
        execute!(out,cursor::MoveTo(0,0),terminal::Clear(ClearType::All))?;
        out.write_all(display.as_bytes())?;
        writeln!(out,"  {}",colored("  [1-14] Choose an action  ·  [Enter] Confirm  ·  [Esc] Exit","2",supports_color()))?;
        write!(out,"  {} {}",colored(">","1;36",supports_color()),
            if entered.is_empty(){format!("[{default}]")}else{entered.clone()})?;
        out.flush()?;

        let remaining=Duration::from_secs(10).saturating_sub(last.elapsed());
        if event::poll(remaining)? {
            if let Event::Key(key)=event::read()? {
                if key.kind!=KeyEventKind::Press{continue;}
                match key.code{
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>return Ok("12".into()),
                    KeyCode::Char('q'|'Q')|KeyCode::Esc=>return Ok("12".into()),
                    KeyCode::Char(ch) if ch.is_ascii_digit() && entered.len()<2=>entered.push(ch),
                    KeyCode::Backspace=>{entered.pop();},
                    KeyCode::Enter=>{
                        return Ok(if entered.is_empty(){default.to_string()}else{entered});
                    }
                    _=>{},
                }
            }
        }
        if last.elapsed()>=Duration::from_secs(10){
            monitor.refresh();
            last=Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> MenuView<'static> {
        MenuView {
            version: "3.2.2",
            region: "iran",
            peer: "203.0.113.10",
            transport: "udp",
            port: Some(444),
            service: "active",
            configured: true,
            resources: Resources::default(),
        }
    }

    #[test]
    fn all_options_keep_original_numbers_and_labels() {
        let text = render(&view(), false, false);
        for i in 1..=14 {
            assert_eq!(text.matches(&format!("{i:>2})")).count(), 1, "menu option {i}");
        }
        for heading in ["LIVE TUNNEL OVERVIEW", "SERVICE CONTROLS", "SETUP & CONFIGURATION", "DIAGNOSTICS", "MAINTENANCE"] {
            assert!(text.contains(heading));
        }
        assert!(text.contains("UDP / 444"));
        assert!(text.contains("203.0.113.10"));
        assert!(!text.contains("\x1b["));
    }

    #[test]
    fn unicode_and_color_only_when_selected() {
        let fancy = render(&view(), true, true);
        assert!(fancy.contains("┌") && fancy.contains("│"));
        assert!(fancy.contains("\x1b["));
        let basic = render(&view(), false, false);
        assert!(basic.contains("+--"));
        assert!(!basic.contains('┌') && !basic.contains("\x1b["));
    }

    #[test]
    fn unconfigured_has_safe_display_without_secrets() {
        let mut data = view();
        data.configured = false;
        data.region = "unknown";
        data.peer = "-";
        data.port = None;
        data.service = "inactive";
        let text = render(&data, false, false);
        assert!(text.contains("option 6"));
        assert!(text.contains("Not configured"));
        assert!(text.contains("inactive"));
        assert!(!text.contains("pair_key"));
    }

    #[test]
    fn service_states_do_not_change_actions() {
        let mut data = view();
        data.service = "failed";
        let text = render(&data, false, false);
        assert!(text.contains("failed"));
        assert!(text.contains("14) Health check"));
        assert!(text.contains(" 6) Setup Wizard"));
    }
    #[test]
    fn resource_summary_carries_sample_and_rolling_means() {
        let mut v=view();
        v.resources=Resources{cpu_percent:Some(12.5),cpu_average:Some(8.2),
            ram_mib:Some(24.4),ram_average:Some(22.1),samples:6};
        let text=render(&v,false,false);
        for value in ["CPU (10s)","12.5%","8.2%","RAM (RSS)","24.4 MiB","22.1 MiB","10s"]{
            assert!(text.contains(value),"missing {value}");
        }
        v.resources=Resources::default();
        let inactive=render(&v,false,false);
        assert!(inactive.contains("—"));
    }

}
