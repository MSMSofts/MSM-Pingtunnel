//! Lightweight /proc monitor for the systemd-owned Go tunnel.
//! Nothing runs in the background when the manager menu is closed.
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const WINDOW: usize = 6; // six 10-second observations = the recent minute

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Resources {
    /// 100% means one fully occupied vCPU. Multiple vCPUs may exceed 100%.
    pub cpu_percent: Option<f64>,
    pub cpu_average: Option<f64>,
    pub ram_mib: Option<f64>,
    pub ram_average: Option<f64>,
    pub samples: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Usage {
    pid: u32,
    start_ticks: u64,
    cpu_ticks: u64,
    rss_kib: u64,
}

fn proc_stat(raw: &str) -> io::Result<(u64, u64)> {
    // /proc/PID/stat: field 2 is a parenthesized command, which may contain
    // whitespace and parentheses. The fields following the last ')' start at 3.
    let end = raw.rfind(')').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,"invalid process stat"))?;
    let tail: Vec<&str> = raw[end + 1..].split_whitespace().collect();
    let parse = |index: usize| -> io::Result<u64> {
        tail.get(index)
            .ok_or_else(||io::Error::new(io::ErrorKind::InvalidData,"missing process stat field"))?
            .parse::<u64>()
            .map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"bad process counter"))
    };
    // tail[0] is field 3; utime=14, stime=15, starttime=22.
    let total=parse(11)?.saturating_add(parse(12)?);
    Ok((total,parse(19)?))
}

fn rss_status(raw: &str) -> io::Result<u64> {
    let row = raw.lines().find(|line|line.starts_with("VmRSS:"))
        .ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"VmRSS unavailable"))?;
    row.split_whitespace().nth(1)
        .ok_or_else(||io::Error::new(io::ErrorKind::InvalidData,"VmRSS missing"))?
        .parse::<u64>()
        .map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"VmRSS invalid"))
}

fn usage_from(proc_root: &Path, pid: u32) -> io::Result<Usage> {
    let dir=proc_root.join(pid.to_string());
    let stat=fs::read_to_string(dir.join("stat"))?;
    let (cpu_ticks,start_ticks)=proc_stat(&stat)?;
    let rss_kib=rss_status(&fs::read_to_string(dir.join("status"))?)?;
    Ok(Usage{pid,start_ticks,cpu_ticks,rss_kib})
}

fn main_pid() -> Option<u32> {
    let output=Command::new("systemctl")
        .args(["show","pingtunnel.service","--property=MainPID","--value"])
        .output().ok()?;
    if !output.status.success(){return None}
    let pid=String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().ok()?;
    (pid>0).then_some(pid)
}

fn cpu_hz() -> f64 {
    let value=unsafe{libc::sysconf(libc::_SC_CLK_TCK)};
    if value>0 {value as f64} else {100.0}
}

pub(crate) struct ResourceMonitor {
    last: Option<(Usage,Instant)>,
    cpu_window: VecDeque<f64>,
    ram_window: VecDeque<f64>,
    visible: Resources,
}

impl ResourceMonitor {
    pub(crate) fn new() -> Self {
        Self{last:None,cpu_window:VecDeque::with_capacity(WINDOW),
            ram_window:VecDeque::with_capacity(WINDOW),visible:Resources::default()}
    }
    pub(crate) fn current(&self)->Resources {self.visible}

    pub(crate) fn refresh(&mut self) {
        let reading=main_pid().and_then(|pid| usage_from(Path::new("/proc"),pid).ok());
        self.update_with(reading,Instant::now(),cpu_hz());
    }

    fn update_with(&mut self, usage:Option<Usage>, now:Instant, hz:f64) {
        let Some(next)=usage else {
            self.last=None;
            self.cpu_window.clear();
            self.ram_window.clear();
            self.visible=Resources::default();
            return;
        };
        let same=self.last.as_ref().map(|(old,_)|
            old.pid==next.pid && old.start_ticks==next.start_ticks).unwrap_or(false);
        if !same {
            // A systemd restart or PID reuse begins a completely new averaging window.
            self.cpu_window.clear();
            self.ram_window.clear();
            self.visible=Resources::default();
        }
        let ram=next.rss_kib as f64/1024.0;
        Self::push(&mut self.ram_window,ram);
        self.visible.ram_mib=Some(ram);
        self.visible.ram_average=Some(Self::average(&self.ram_window));
        if same {
            let (old,older)=self.last.unwrap();
            let duration=now.saturating_duration_since(older).as_secs_f64();
            if duration>0.0 && hz>0.0 && next.cpu_ticks>=old.cpu_ticks {
                let percent=100.0*(next.cpu_ticks-old.cpu_ticks) as f64/(hz*duration);
                if percent.is_finite(){
                    Self::push(&mut self.cpu_window,percent);
                    self.visible.cpu_percent=Some(percent);
                    self.visible.cpu_average=Some(Self::average(&self.cpu_window));
                }
            }
        } else {
            self.visible.cpu_percent=None;
            self.visible.cpu_average=None;
        }
        self.visible.samples=self.cpu_window.len();
        self.last=Some((next,now));
    }

    fn push(window:&mut VecDeque<f64>, value:f64){
        if window.len()==WINDOW{window.pop_front();}
        window.push_back(value);
    }
    fn average(window:&VecDeque<f64>)->f64{
        window.iter().copied().sum::<f64>()/window.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn p(pid:u32,start:u64,ticks:u64,rss:u64)->Usage{
        Usage{pid,start_ticks:start,cpu_ticks:ticks,rss_kib:rss}
    }
    #[test]
    fn handles_parenthesized_comm_with_spaces(){
        let mut fields=vec!["0";21];fields[0]="S";fields[11]="120";fields[12]="40";fields[19]="199";
        let s=format!("42 (go worker (abc)) {}",fields.join(" "));
        assert_eq!(proc_stat(&s).unwrap(),(160,199));
    }
    #[test]
    fn rss_reads_only_vmrss(){
        assert_eq!(rss_status("Name:\ttunnel\nVmPeak:\t456 kB\nVmRSS:\t30720 kB\n").unwrap(),30720);
        assert!(rss_status("Name:\ttunnel").is_err());
    }
    #[test]
    fn averages_last_six_and_resets_on_restart(){
        let mut m=ResourceMonitor::new();let start=Instant::now();
        m.update_with(Some(p(42,11,0,10240)),start,100.0);
        assert_eq!(m.current().cpu_percent,None);
        for i in 1..=8u64 {
            m.update_with(Some(p(42,11,i*50,10240+i*1024)),
                start+Duration::from_secs(i*10),100.0);
        }
        assert_eq!(m.current().samples,6);
        assert!((m.current().cpu_average.unwrap()-5.0).abs()<0.01);
        assert!((m.current().ram_average.unwrap()-15.5).abs()<0.01);
        m.update_with(Some(p(42,12,10,4096)),start+Duration::from_secs(90),100.0);
        assert_eq!(m.current().samples,0);
        assert!(m.current().cpu_average.is_none());
        assert_eq!(m.current().ram_mib,Some(4.0));
        m.update_with(None,start+Duration::from_secs(100),100.0);
        assert!(m.current().ram_mib.is_none());
    }
    #[test]
    fn cpu_can_exceed_one_core(){
        let mut m=ResourceMonitor::new();let t=Instant::now();
        m.update_with(Some(p(42,11,100,4096)),t,100.0);
        m.update_with(Some(p(42,11,300,4096)),t+Duration::from_secs(1),100.0);
        assert!((m.current().cpu_percent.unwrap()-200.0).abs()<0.001);
    }
}
