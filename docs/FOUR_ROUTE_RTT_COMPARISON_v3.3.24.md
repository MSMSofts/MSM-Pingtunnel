# v3.3.24 — Four ICMP route policies: measured UDP RTT comparison

[فارسی](#مقایسه-فارسی) · [CI run with full logs](https://github.com/MSMSofts/MSM-Pingtunnel/actions/runs/43178280092) · [Stable v3.3.24](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.24)

## English: real Linux-namespace CI measurement, **not public-Internet ping**

This table comes from the **successful** GitHub Actions v3.3.24 release-candidate run on **2026-11-12**. The test runs the actual Linux Go core on two network namespaces connected with a veth pair. It passes real Wire-v4-authenticated UDP echo traffic through ICMP. Values are observed **application UDP echo round-trip times**, *not* ICMP `ping`, real two-VPS latency, gaming RTT or guaranteed performance.

| Policy | Started direction | Automatic switching? | Baseline p50 / p95 RTT | Impaired p50 / p95 RTT | After restore p50 / p95 RTT | Echo replies after restore |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Manual Direct | Direct | No | 0.4 / **0.5 ms** | 50.7 / **64.7 ms** | 49.2 / **58.5 ms** | 28/32 (12.5% lost) |
| AUTO Direct-first | Direct | Yes: Direct → Reverse on confirmed failure; verified return to Direct | 0.4 / **0.6 ms** | 49.8 / **62.4 ms** | 53.7 / **64.9 ms** | 28/32 (12.5% lost) |
| Manual Reverse | Reverse | No | 4.7 / **4.9 ms** | 59.7 / **75.5 ms** | 58.2 / **81.4 ms** | 30/32 (6.2% lost) |
| AUTO Reverse-first | Reverse | Yes: Reverse → Direct on confirmed failure; verified return to Reverse | 4.7 / **5.0 ms** | 57.8 / **69.0 ms** | 61.7 / **72.6 ms** | 30/32 (6.2% lost) |

`p50` is the median and `p95` the 95th percentile among **successfully received** replies. Lost packets have **no measured RTT** and appear in separate loss counts, so comparing p95 without loss would be misleading.

### Fault-injection profile and interpretation

- **Baseline:** 24 UDP echo probes per mode, all 24 replied. No emulated network impairment.
- **Impaired:** 32 probes with `tc netem` on each namespace's egress veth: 25ms ±9ms delay, 4% random loss, 2% reordering. There is impairment in both directions, so the observed total loss is not simply 4%.
- **One-way outage:** Iran-originated egress is temporarily set to **100% packet loss**; three uniquely tagged test requests receive **0/3** replies in every mode. This verifies the one-way blackhole rather than implying that any tunnel can bypass a fully blocked path.
- **Restored:** the Iranian egress is restored to the **impaired** 25ms/loss/reorder profile (not to the clean baseline); another 32 uniquely tagged packets are sent **without restarting either Go process**.
- This is a **short outage**, deliberately shorter than the AUTO path-switch grace. The tests prove continued authentication/recovery after restoring a link, **not** completed AUTO failover to the secondary route under a 90–150-second outage.
- Numbers are one CI sample, not a controlled repeated performance study. The 0.5–5ms baseline difference under this local environment does **not** prove Direct is faster on a particular provider or real Iran↔overseas route.

### Choosing a route

| Scenario | Suitable option | Why |
| --- | --- | --- |
| Prefer Reverse and keep a verified Direct fallback | **AUTO Reverse-first** | Stable preferred Reverse, retries Direct after sustained authenticated failure |
| Prefer Direct when your providers pass Direct ICMP | **AUTO Direct-first** | Uses Direct normally; switches toward verified Reverse upon genuine failure |
| Diagnose and keep Direct locked | **Manual Direct** | Reproducible fixed path; never switches even if dead |
| Diagnose and keep Reverse locked | **Manual Reverse** | Reproducible fixed path; never switches even if dead |

Use the **same route policy on both peers**. To choose what is faster for a real game, run comparable tests on your actual two VPSs, using the same UDP/TCP application, time window and load, with RTT p50/p95/p99, jitter, loss, disconnects and failover time. **Do not select modes by the above CI milliseconds alone.**

## مقایسه فارسی

این اعداد مربوط به **آزمایش دو فضای شبکه ایزوله در GitHub Actions** است؛ مسیر واقعی اینترنت بین ایران و خارج اندازه‌گیری نشده است. منظور از پینگ در جدول، زمان رفت‌وبرگشت پیام UDP رمزنگاری‌شده در داخل ICMP است.

| حالت | جهت شروع | تغییر خودکار مسیر | پینگ پایه P95 | پینگ اختلال P95 | پینگ پس از بازیابی P95 | پاسخ پس از بازیابی |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| **Direct دستی** | مستقیم | ندارد | **0.5 ms** | **64.7 ms** | **58.5 ms** | ۲۸ از ۳۲ |
| **AUTO Direct-first** | مستقیم | بعد از خرابی تأییدشده به Reverse و بازگشت تأییدشده | **0.6 ms** | **62.4 ms** | **64.9 ms** | ۲۸ از ۳۲ |
| **Reverse دستی** | معکوس | ندارد | **4.9 ms** | **75.5 ms** | **81.4 ms** | ۳۰ از ۳۲ |
| **AUTO Reverse-first** | معکوس | بعد از خرابی تأییدشده به Direct و بازگشت تأییدشده | **5.0 ms** | **69.0 ms** | **72.6 ms** | ۳۰ از ۳۲ |

**معنی P95:** ۹۵ درصد از پاسخ‌های *دریافت‌شده* در آن مرحله، زمان رفت‌وبرگشتی حداکثر برابر این عدد داشته‌اند. بسته‌های گم‌شده در این محاسبه حضور ندارند.

**روش آزمایش:** روی هر دو جهت شبکه، تأخیر ۲۵ میلی‌ثانیه با نوسان ۹ میلی‌ثانیه، افت ۴ درصد و تغییر ترتیب ۲ درصد شبیه‌سازی شد؛ سپس مسیر خروجی ایران برای مدتی کوتاه کاملاً مسدود و دوباره به همان وضعیتِ دارای اختلال بازگردانده شد. در هیچ‌یک از این مراحل هسته Go راه‌اندازی مجدد نشد. چون قطعی کوتاه‌تر از مهلت Failover است، **این تست وقوع جابه‌جایی خودکار مسیر را ثابت نمی‌کند**.

**پیشنهاد انتخاب:** برای پایداری با اولویت Reverse، حالت AUTO Reverse-first مناسب است؛ برای اولویت Direct در شبکه‌ای که ICMP مستقیم مجاز است، AUTO Direct-first. حالت دستی برای قفل‌کردن مسیر یا عیب‌یابی مناسب‌تر است. انتخاب نهایی را با اندازه‌گیری روی هر دو VPS واقعی انجام دهید.
