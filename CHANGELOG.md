# Changelog / تاریخچه تغییرات

## [3.3.12 preview] — Emergency safe-by-default framing hotfix

- **Connectivity regression:** v3.3.11 FEC rewrote the count field of BOTH original UDP fragments, making their reassembly incompatible with v3.3.10 during mixed-version operation.
- **Fail-safe default:** Disable both ICMP segmentation and UDP FEC unless explicitly enabled on both peers; default encrypted datagram wire behavior matches the known-working v3.3.8.
- Optional parity is now a distinct AEAD-encrypted PTF5 extension; original PTF4 data fragments retain their previous bytes, so a v3.3.10 peer can still reconstruct ordinary fragments.
- Strict manager/core validation prevents enabling FEC without segmentation, and regression tests cover unchanged original data plus disabled-by-default settings.
- Not a measured Reels-speed fix. Use a 2-VPS staging pair before re-enabling fragmentation; preserve v3.3.8 rollback. [Hotfix design](docs/3312_EMERGENCY_COMPATIBILITY.md).


## [3.3.11 preview] — Bounded UDP repair parity for 2-part ICMP datagrams

- Added optional-by-budget XOR parity (maximum 24 repair frames per second) for two-fragment UDP DATA. Independently AEAD-authenticated parity permits receiver reconstruction with **one missing segment**, without delivering partial UDP payloads. TCP/large multi-part packets receive no parity.
- Parity uses a version-specific encrypted fragment-header flag; the 1200-byte IPv4 budget, reverse-queue handling, and v3 security/replay protection are retained. 256 recently completed IDs avoid late-parity duplicate delivery.
- Added CI tests for first/second segment loss, no-loss normal delivery, malformed parity, strict sender rate caps, and bounded receiver memory; and security counters for generated parity/recovered UDP datagrams.
- **Both VPS cores must be upgraded together**: v3.3.10 cannot interpret the flagged chunks. This prerelease is not field-proven to reduce Instagram Reels stalls; extra parity can worsen congestion on ICMP-limited links. [Technical details](docs/UDP_FEC_LOSS_RECOVERY.md).


## [3.3.10 preview] — Authenticated ICMP packet segmentation and safe maintenance

- Keep full serialized UDP datagrams but independently AEAD-authenticate chunks of large protobuf messages. Bound each IPv4/ICMP packet to 1200 bytes, reconstruct only complete datagrams with 3-second TTL and 2 MiB bounded reassembly memory.
- Preserve the original encrypted wire frame for small messages. Big messages require **both VPSs on 3.3.10**: older receivers cannot decode this authenticated fragment payload extension. There is no claim of cross-version UDP compatibility or zero network packet loss.
- Independent Auto Tune preview/explicit apply and robust uninstall from hardening PR #30; kernel ICMP write, fragmentation and incomplete-group counters in `pingtunnel security`.
- v3.3.10 is a **preview release** pending real end-to-end Exclave/Reels and MTU comparisons. Do not run on just one side; retain v3.3.8 rollback.


## Unreleased — Safety hardening (not a v3.3.9 hotfix)

- Auto Tune becomes preview-only by default. An explicit `--apply` is necessary for a disruptive restart; Foreign exits without side effects.
- Conservative stability gate rejects tuning on unreliable/poorly sampled paths. Probe-loss is explicitly identified as an EWMA, not UDP application packet loss.
- Uninstall handles partial previous removal, deletes runtime files and all dedicated unit drop-ins; irreversible `--purge` requires a separate `PURGE` confirmation and preserves the manager until cleanup succeeds.
- Regression remains unverified: baseline v3.3.8 and v3.3.9 share Reverse ICMP and AEAD implementation, but real two-VPS MTU/UDP behavior must be measured before claiming a transport fix.


## [3.3.9](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.9) — Authenticated TCP/UDP path Auto Tune

**Schema 3 · Secure wire v4 · No cryptographic, pairing or ICMP direction changes**

- New option **15) Auto Tune** and `pingtunnel auto-tune [--dry-run]` on the Iran client: tests ordinary/sized IPv4 ICMP as *diagnostics* and only tunes from **8 authenticated RTT observations within 120 seconds**, newest within 35 seconds. Existing Go RTT estimator and online TCP congestion stay active.
- Conservative bounded TCP buffer/window/RTO/idle-timeout profiles; UDP socket read/write buffers and UDP idle-timeout profiles, without assigning TCP framing semantics to UDP.
- For authenticated UDP traffic only, the existing (previously unused) TCP buffer value carries an optional bounded UDP socket queue preference to new foreign cores. No protobuf field or wire-version change; old peers ignore the preference. Foreign-side loopback/proxied UDP sockets use it subject to kernel caps. Datagram MTU and QUIC/Hysteria application congestion are not modified.
- Before changes, save a 0600 configuration backup; after restart require new systemd PID, fresh Go status and authenticated return traffic within 45 seconds. Restore prior settings on failure. CLI preview makes no changes.
- Strong input/peer bounds, transport-specific CLI diagnostics, compatible Setup persistence, Rust/Go regression coverage, Go race tests, and AMD64/ARM64 builds. **Live two-VPS throughput, loss and jitter benchmarking remains necessary; measured optimal performance is not guaranteed.**
- Installer, manager, Go core and CI release manifest all agree on v3.3.9. Upgrade both peers for foreign-side UDP socket preference support.


## [3.3.8](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.8) — Exact encrypted PING echo filtering and active TTL signature pruning

**Schema 3 · Secure wire v4 · No encryption, protocol layout, Reverse-first or BBR changes**

- In a 47-second foreign-VPS playback test, the v3.3.7 PTD4 DATA reflection filter removed **4,277** exact Echo reflections while **34 authentication errors** remained (~0.72 errors/s). The foreign host periodically emits authenticated PING messages as encrypted PTD4 Echo Requests; v3.3.7 tracked only DATA, leaving PING and other secure-message kernel reflections unmatched. This is a plausible error source, not yet independently proven.
- The foreign sender now stages an exact **full-ciphertext SHA-256 + ICMP ID + Echo sequence** signature for all outbound **encrypted PTD4 Echo Requests** (DATA, PING, other). Matching still requires the correct pinned peer address, Type 0 Echo Reply and an 8-second TTL. Different encrypted Iran→Foreign frames, including Hysteria/QUIC ACKs, continue to pass through normal AEAD verification.
- Crucially, **only real outbound DATA** accelerates adaptive reverse polling; tracking PING/KICK does not alter the existing 2/4/6/12/25 ms DATA-driven schedule.
- Fixed the stale cache diagnostic: a bounded 16,384-entry chronological ring now reclaims expired/canceled oldest signatures on send, receive and status reads, O(1) amortized. Full-capacity eviction still removes the oldest remaining signature. Failed socket writes cancel their registrations.
- Separate diagnostics: `reverse_data_echo_reflections`, `reverse_ping_echo_reflections`, `reverse_other_echo_reflections`, `reverse_echo_cache_expired`, `reverse_echo_cache_capacity_evicted`, and active `reverse_data_echo_cache_entries`.
- Go regressions test Ping-vs-DATA classification, exact type/id/sequence/ciphertext matching, no accidental BBR poll acceleration, TTL expiration under steady load and idle, bounded capacity eviction, failure rollback and concurrent tracking under race detection.
- **Limit:** An improved error rate or video playback must be verified after installing on both real VPSs. Nothing here proves zero ICMP loss or fixes all QUIC stalls.


## [3.3.7](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.7) — Discard only exact Linux PTD4 ciphertext Echo reflections

**Schema 3 · Secure wire v4 · No packet, crypto, Reverse-first or BBR configuration changes**

- The user captured 3,512 ICMP PTD4 packets over 10 seconds on the overseas VPS: **1,465 outbound encrypted Echo Requests** and **2,047 inbound PTD4 Echo Replies**, of which **1,453** were byte-identical reflected copies of locally sent requests (including identical ICMP ID and sequence). The remaining 594 replies were unmatched and may contain legitimate Iran→Foreign QUIC acknowledgements.
- Unlike the previous fixed-marker PTR4 reflection filter, the new **PTD4 filter never drops packets by magic bytes alone**: foreign tracks a SHA-256 digest of each outgoing encrypted DATA payload with its ICMP Echo ID/sequence and discards only a matching Type 0 Echo Reply from the already IP-pinned peer, before receiving-side decryption.
- Race-safe registration is staged **before** raw socket writing; failed writes cancel registration. A bounded **16,384-entry ring/map** with an **8-second maximum reflection matching age** prevents indefinite memory growth or matching old ciphertext. Only full ciphertext digests and Echo metadata are stored, not plaintext.
- New telemetry: `reverse_data_echo_reflections` and `reverse_data_echo_cache_entries`, shown in `pingtunnel security` as `Filtered exact PTD4 Echo reflections` and `Outbound PTD4 reflection cache entries`. Authentication-failure counters are reserved for other invalid frames.
- Regression coverage checks exact reflected Echo frames, distinct genuine PTD4 payloads (including same ICMP ID/sequence), type/region restrictions, timeout, write rollback, memory cap/eviction and concurrent access (including race testing).
- **Validation:** No asserted reduction in playback buffering until paired VPS installation and video re-testing; the transport still cannot guarantee zero ICMP packet loss or independent QUIC-layer reliability.


## [3.3.6](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.6) — BBR short-jitter Reverse polling and rolling queue-delay P95

**Config schema: 3 · Secure wire: 4 · No application packet framing, encryption or BBR configuration change**

- The foreign poller retains quick return opportunities for QUIC ACK/loss recovery during 1–3-second video stalls: sustained authenticated Iran→Foreign DATA keeps 2ms target pacing for up to 2.4s; sustained successfully written Foreign→Iran DATA keeps 4ms for up to 4.5s before stepping down to 6/12/25ms. Only actual DATA refreshes the windows; a single outbound frame cannot trigger 2ms polling; idle and handshake cadences stay at 250ms and 200ms.
- Iran's Reverse queue diagnostics now include `reverse_mean_delivery_delay_ms`, `reverse_p95_delivery_delay_ms`, `reverse_delivery_delay_samples` and `reverse_very_delayed_frames`. The bounded 128-frame ring contains **successful socket writes only**. Mean and nearest-rank P95 cover the most recent successful sends, rather than the lifetime maximum.
- Failed Echo Reply writes, empty polls and expired queued frames do not count as deliveries. Failed frames retain their original queue deadline and can be retried in order.
- New tests cover steady active-but-idle sessions, short BBR jitters, gradual cool-down, idle recovery and transient 1-second queue-delay P95 spikes versus an all-healthy rolling window.
- Retains v3.3.5's replay cache capacity fix and v3.3.3's kernel Echo reflection filtering, unchanged Reverse-first Auto behavior and emergency-only Direct fallback.
- **Field limitation:** Better buffering is a hypothesis, not an established result. Compare video playback and P95 on both VPSs; low queue residence does not rule out ICMP loss or Hysteria's QUIC congestion behavior.


## [3.3.5](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.5) — Prevent Reverse poll replay-cache saturation

**Config schema: 3 · Secure wire: 4 · No external packet layout or cryptographic changes**

- Corrected a capacity mismatch: a 500Hz authenticated Reverse poller with 20-second replay protection can maintain roughly **10,000** valid nonces concurrently, but the existing cache rejected fresh requests once it reached **4,096**.
- Increased the bounded Iran-side cache to **16,384** while retaining HMAC checks, the 20-second validity window, nonce replay rejection and periodic pruning. Overflow remains rejected rather than disabling security.
- Exposed `reverse_replay_capacity_rejections` in local security JSON and in `pingtunnel security`. It distinguishes cache exhaustion from replay or authentication errors.
- Added regression tests for 10,000 valid signed polls over a 20-second simulated 500pps interval and explicit overflow/replay rejection.
- Preserves the successfully written downlink DATA-driven scheduling and measured queue delays introduced in 3.3.4; maintains Reverse-first with emergency-only Direct.
- **Validation limitation:** this corrects a demonstrable polling-capacity bug; improvement to the user's intermittent 1–3-second video stalls still requires paired VPS playback measurements.


## [3.3.5](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.5) — Fix signed reverse poll replay cache saturation under continuous video load

**Secure wire v4 and config schema 3 unchanged.**

- The Reverse ICMP poller can send up to 500 authenticated Echo Requests per second. Its 20-second replay-prevention window may therefore contain about 10,000 legitimate nonces. The old hard limit of 4,096 could reject healthy polling traffic after several seconds of sustained maximum-rate video activity.
- The bounded replay cache now permits 16,384 recent nonces. HMAC authentication, timestamp freshness checks, nonces and duplicate rejection stay enabled; expired entries remain pruned.
- `reverse_replay_capacity_rejections` is now reported separately in runtime security status and the terminal diagnostics. High values indicate rejected signed polls due to an exhausted cache, not a valid authentication failure.
- Added a regression covering 10,000 individually authenticated 2-ms interval polls over 20 seconds, rejection of a replayed nonce and memory reclamation after expiration.
- Builds on the existing v3.3.4 bidirectional Hysteria ACK-aware polling changes, with no change to packet framing, Reverse-first priority or Direct emergency fallback.
- Field playback and throughput still need measurement: the absence of replay saturation cannot by itself prove a specific video-stall reduction.


## [3.3.4](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.4) — Reduce Hysteria/QUIC reverse-path ACK latency

**Config schema: 3 · Secure wire: 4 · No packet-format or encryption change**

- Addressed a bidirectional scheduling mismatch: high-volume **Foreign→Iran** video DATA did not previously accelerate the foreign-origin polling needed to return **Iran→Foreign** QUIC ACKs. The scheduler now reacts to both successfully written Foreign→Iran DATA and authenticated Iran→Foreign DATA.
- Responsive but bounded target poll intervals: 25 ms for an open quiet session, 12 ms after video activity begins and during short breaks, 4 ms during sustained Foreign→Iran video streaming, 2 ms for sustained authenticated incoming return traffic, 250 ms idle, and 200 ms while negotiating. Polling cools gradually after bursts instead of immediately falling back to the previous 80 ms active-session cadence.
- Iran's bounded outgoing queue now reports the *oldest waiting frame age*, last and maximum successful queue delivery delay, the number of successfully sent frames, and successful frames that waited >=250 ms. A failed raw socket write or empty poll never counts as a successful delivery.
- The overseas status reports how long ago it successfully sent video/application DATA to Iran. These new metrics make it possible to distinguish buffering due to return ACK starvation from ICMP packet loss, MTU fragmentation or Hysteria's own congestion control.
- Existing Reverse-first priority, emergency Direct fallback thresholds, authenticated PTR4 reflection filtering, queue limits, X25519/AEAD and wire v4 remain unchanged.
- Go tests cover video-driven poll acceleration/cooling and precise delay accounting, including failure and empty-queue cases. Go race tests and Rust builds run on both amd64/arm64.
- **No throughput claim:** The reported 1–3 second recurring playback stalls are the motivation, not a measured result of this release. Confirm on real VPSs by comparing playback and queue age/delay before and after installation.


## [3.3.3](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.3) — Separate kernel Echo reflections from authenticated DATA

**Config schema: 3 · Wire version: 4 · No packet-layout, crypto or direction changes**

- Confirmed in a real-world VPS diagnostic that the foreign host receives kernel-reflected 44-byte ICMP Echo Replies with the same 36-byte `PTR4` payload as outbound Reverse poll requests (491 in a 10-second capture).
- The overseas Go receive path now filters **only** ICMP Type 0 Echo Replies whose payload is **exactly 36 bytes and starts with PTR4**, after checking the paired peer's IP and before sending the payload to the AEAD decoder.
- The filter cannot match normal `PTD4` authenticated DATA or `PTH4` control handshakes; foreign-to-Iran ICMP Requests and Iran-side decoding are unchanged.
- New `reverse_poll_echo_reflections` field and `Filtered kernel PTR4 Echo reflections` manager metric track what the **Go receiver**, rather than tcpdump, actually filters. Such reflections no longer inflate the session's `authentication_failures` counter.
- Regression tests cover a real 44-byte ICMP Echo Reply frame, source-role/type/length filtering, false-positive avoidance and metric isolation. Go and Rust CI remain required before release.
- **Limit:** This corrects excess decryption attempts and misleading authentication error diagnostics. It does **not** establish that the user's Hysteria/Shorts buffering issue is resolved; queue wait time, packet loss and playback must be assessed independently.


## [3.3.2](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.2) — Reverse first, Direct only after sustained actual failure

**Config schema: 3 · Wire protocol: 4 · Exact same authenticated ICMP framing**

- Corrected the v3.3.1 Auto regression that unconditionally left Reverse after a 25-second incomplete handshake; a short negotiation delay is NOT sufficient evidence of network failure.
- **Reverse is the sticky default.** While authenticated Reverse probes or valid encrypted session traffic are still arriving, Auto does not switch to Direct just because the application is idle or response traffic is sparse.
- A fallback now requires **continuous local demand** and sustained failure: no valid reverse polls after 90 seconds, a repeatedly unconfirmed four-step handshake despite valid polls after 150 seconds, or no valid reverse polls AND no authenticated messages for 150 seconds on an established session.
- Observed Reverse outages are not hidden: `pingtunnel security` and `pingtunnel health` report `auto_direct_fallback_count` and the explicit last fallback reason. Data discarded during a mode change counts toward queue drops.
- Regression tests check the 25-second delay, 24-hour idle Reverse, ongoing valid polls without app data, intermittent traffic, true prolonged outages and Direct handshakes.
- These grace periods prioritize keeping a working Reverse path, not minimizing time to emergency Direct. A completely broken Reverse connection can be unavailable for more than a minute before automatic fallback.
- No change to pairing key, wire version, ICMP Echo format or application-specific cryptographic envelopes; all paired endpoints must be upgraded together for consistent behavior.


## [3.3.1](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.1) — تطبیق Poll معکوس با بار واقعی و بازیابی صف

**Config schema: 3 · Secure wire: 4 · No new external packet framing**

- The overseas VPS now uses an **event-driven adaptive timer** rather than waking every 2 ms while idle. The nominal reverse polling delay is **200 ms during handshake / 250 ms idle / 80 ms during quiet active connections / 40 ms after one useful authenticated data frame / 12 ms after a small burst / 2 ms during sustained throughput**. Poll intervals are load-aware, not network congestion guarantees.
- Multiple useful authenticated frames must arrive in a short period before moving to the fastest 2 ms polling cadence; an isolated datagram can no longer trigger hundreds of speculative polls per second.
- The Iran server no longer generates a **redundant userspace empty Echo Reply** for idle polls. Existing kernel Echo behavior remains under host control. Encrypted queued application frames still receive explicit matching Echo Replies.
- A sparse, authenticated receipt from Foreign (at most once per 8s when valid Iran→Foreign DATA was received within 10s) prevents false timeouts during long one-way transfers. It is only generated after genuine encrypted data arrives, never in response to untrusted ordinary Ping.
- **Failed userspace ICMP write:** encrypted queued payload is restored at the FIFO head without renewing its original 12-second lifetime. Oldest/overflow and write failure accounting remain explicit and bounded.
- Fixed the foreign-side Echo Reply type while attempting Direct fallback after Reverse, without weakening handshake validation or accepting unauthenticated data.
- `sudo pingtunnel security` now reports reverse queue depth/bytes, peak size, dropped frames, failed reply writes, recent authenticated payload age and the actual selected polling interval.
- Added regression tests for failed writes, FIFO preservation, load adaptation, queue saturation under concurrency and idle duplicate suppression. CI builds and race checks cover amd64/arm64.
- **Operational note:** Reverse connectivity was reported working on a real VPS pair with v3.3.0. This release's performance and packet-loss characteristics still require measured field testing. ICMP rate limiting, kernel replies and network filtering remain outside the guarantees of CI.


## [3.3.0](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.0) — Reverse-first ICMP Auto

**Config schema: 3 · Wire protocol: 4 · Both paired VPSs must use matching 3.3.0 binaries**

- Auto defaults to **Reverse** at startup: the overseas VPS sends HMAC-authenticated ICMP Echo Requests; the Iran VPS returns encrypted application frames within matching Echo Replies.
- If the initial Reverse handshake is not completed after 25 seconds, Iran retries in **Direct**. Healthy links are retained; transitions are protected by a minimum 60-second dwell.
- Reverse polling is bounded, supports signed timestamp/nonce replay checks and a bounded response queue; stale application frames expire after 12 seconds.
- The authenticated ephemeral X25519 exchange and per-direction AEAD session keys are preserved; no plaintext downgrade is allowed.
- When the application is quiet, signed Reverse polls are reported separately from authenticated two-way traffic; they never falsely mark a broken return path as healthy.
- Integration tests cover the entire Reverse handshake in ICMP Echo Request/Reply frames, bidirectional encrypted data, duplicate rejection, and Direct fallback.
- **Operational limitation:** CI and race tests cannot establish filtering resistance or reproduce a live VPS firewall, automatic kernel Echo Replies, traffic shaping, or network outages. Verify on a nonproduction two-VPS pair before upgrading critical connections.


[README فارسی](README.md) · [English README](README.en.md) · [Releases](https://github.com/MSMSofts/MSM-Pingtunnel/releases)

این فایل از **نسخه 3.0 به بعد** تغییرات اصلی Pingtunnel Manager را ثبت می‌کند. نسخه‌ها فقط با عنوان محصول توصیف نمی‌شوند؛ تغییرات **قالب تنظیمات** و **پروتکل ارتباط بین دو VPS** نیز در هر مرحله مشخص شده‌اند.

## [3.2.6](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.6) — جلوگیری از بازیابی غیرضروری

**Config schema: 3 · Wire protocol: 4**

- Watchdog برای تشخیص قطع ارتباط، ترافیک واقعی احرازشده را هم در کنار Ping در نظر می‌گیرد؛ عبور سالم داده باعث Restart بی‌مورد نمی‌شود.
- هسته و Manager هر دو از Release یکسان 3.2.6 نصب می‌شوند.

## [3.2.5](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.5) — نمایش پایدار Status و بازیابی طولانی‌مدت

**Config schema: 3 · Wire protocol: 4 · No re-pairing required**

- خروجی Status و لاگ‌ها در منوی تعاملی تا Enter بعدی روی صفحه می‌ماند.
- خطای دائمی دریافت ICMP و انسداد صف پردازش بیش از سه ثانیه به systemd گزارش می‌شود تا هسته بازیابی شود.
- اگر اتصال به سرور مقابل با وجود تقاضای مداوم بیش از چهار دقیقه پاسخ ندهد، هسته بازراه‌اندازی می‌شود؛ این سیاست هنگام بیکاری فعال نیست.
- Restart سرویس محدودیت دفعات ندارد، گزارش خطا در journal نگهداری می‌شود و Health هشدار عدم ارتباط احرازشده می‌دهد.
- آدرس مخزن و اسکریپت‌های نصب و به‌روزرسانی با MSM-Pingtunnel هماهنگ شدند.

## [3.2.4](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.4) — رفع خرابی رسم منو و ترتیب گزینه‌ها

**Config schema: 3 · Wire protocol: 4 · No pairing/key/port changes**

- رفع اصلی‌ترین مشکل نسخه 3.2.3: حالت Raw ترمینال ترجمه‌ی سطر جدید را غیرفعال می‌کرد؛ منوی کامل اکنون پیش از ارسال به ترمینال، پایان خطوط را **CRLF** می‌کند تا متن مورب و پلکانی نشود.
- بازنویسی صفحه به ساختار **تک‌ستونه و مرتب 1 تا 14 از بالا به پایین**؛ گروه‌ها به‌ترتیب Service (1–5)، Setup (6–7)، Diagnostics (8–9)، Maintenance (10–12)، Security & Health (13–14) نمایش داده می‌شوند.
- تطبیق نمایش با ابعاد ترمینال و حالت فشرده برای پنجره‌های کوچک؛ پیشگیری از Wrap در ستون آخر و اسکرول ناخواسته در آخر صفحه.
- حفظ نمایش زنده CPU/RAM و میانگین‌ها، تازه‌سازی ۱۰ ثانیه‌ای بدون پاک شدن انتخاب تایپی، حالت ASCII بدون رنگ، و Restart اجباری پس از Update موفق.
- تست‌های رگرسیون برای **CRLF در حالت Raw**، ترتیب دقیق ۱۴ گزینه، طول هر خط در اندازه‌های متفاوت و حالت سرویس خاموش.

## [3.2.3](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.3) — داشبورد زنده و Restart پس از Update

**Config schema: 3 · Secure wire: 4 · Pairing root unchanged**

- پایش CPU ده‌ثانیه‌ای و حافظه RSS فرایند Go Core در بخش وضعیت منوی Rust؛ میانگین غلتان ۶ نمونه برای هرکدام، Reset هنگام تغییر فرایند و نمایش نشانگر `—` در وضعیت بدون داده.
- محیط تعاملی بازترسیم‌شونده هر ۱۰ ثانیه، با حفظ ورودی تایپ‌شده، رنگ‌بندی خواناتر، بازگشت مطمئن به حالت استاندارد ترمینال پیش از اجرای دستور، و حالت جایگزین برای ترمینال‌های غیرتعاملی.
- نصب‌کننده پس از ارتقای معتبر و تنظیم‌شده، **حتماً سرویس تونل را Restart می‌کند** و با بررسی فرایند و Heartbeat، صحت شروع مجدد را می‌سنجد؛ در صورت خطا Rollback حفظ می‌شود.
- بدون Agent جدید، بدون تغییر رمزنگاری، پورت‌ها، Schema 3 یا Wire v4 و بدون نیاز به Pairing مجدد.
- تست‌های واحد مستقل برای شمارنده‌های `/proc`، میانگین ۶ نمونه، تغییر PID، عدم افشای تنظیمات و UI در حالت بدون رنگ.

## [3.2.2](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.2) — بازطراحی منوی ترمینال

**Config schema: 3 · Secure wire: 4 · بدون تغییر در کلید و پروتکل**

- بازطراحی منوی Rust در چهار بخش Service Controls، Setup & Configuration، Diagnostics و Maintenance، با سربرگ مرتب و خلاصهٔ واقعی سرویس و پورت VPS فعلی.
- رنگ‌بندی ملایم و قاب Unicode برای ترمینال‌های سازگار؛ نمایش سادهٔ ASCII بدون ANSI با `NO_COLOR`، ترمینال بدون رنگ یا خروجی غیربرهم‌کنشی.
- حفظ دقیق ۱۴ گزینه، شماره‌ها، مسیرهای پیکربندی، پورت‌ها، امنیت و رفتار systemd. هیچ‌کدام از اسرار جفت‌سازی در خلاصهٔ منو نشان داده نمی‌شود.
- تست‌های مستقل خروجی منو، سازگاری حالت بدون رنگ، تشخیص تنظیمات نامعتبر و حفظ تمام شماره‌گزینه‌ها.
- تکمیل راهنمای تصویریِ متنی منو، شرح تک‌تک گزینه‌ها و پنج سؤال Setup به فارسی و انگلیسی.

**سازگاری:** قالب فایل `schema_version=3` و Wire v4 ثابت‌اند. از نسخه 3.2.1 به 3.2.2 نیازی به اجرای دوباره Setup یا انتقال مجدد کلید نیست؛ Restart سرویس در زمان نصب ممکن است نشست‌های جاری را قطع کند.

## [3.2.1](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.1) — اصلاح هم‌زمانی و سلامت ارتباط

**Config schema: 3 · Secure wire: 4 · بدون نیاز به جفت‌سازی مجدد**

- تبدیل شمارندهٔ ICMP، وضعیت توقف، شمارنده‌های بسته، زمان فعالیت اتصال و شناسه‌های پاسخ مشترک به دسترسی‌های Atomic در Go.
- اصلاح Adaptive Performance با نگهداری Pingهای معلق، تشخیص افت پیوسته پاسخ‌ها و کاهش پارامترهای TCP حتی قبل از اولین RTT موفق.
- ایجاد مانع شروع TCP تا پایان تأیید نشست رمزنگاری با سقف ۴۵ ثانیه، و افزایش فرصت برقراری جریان‌های TCP تا ۱۵ ثانیه.
- تشخیص توقف غیرمنتظرهٔ Goroutineهای اصلی ICMP، دریافت و پردازش و سپردن راه‌اندازی مجدد به systemd؛ سکوت عادی شبکه به‌تنهایی موجب Restart نمی‌شود.
- فرمان `pingtunnel health`، بررسی تازه‌بودن Heartbeat هسته Go و نظارت فرایند پس از Restart در نصب‌کننده، همراه Rollback در صورت خطا.
- تصحیح مسیرهای انتقال مخزن به `MSMSofts/MSM-Pingtunnel` و انتشار نسخه ثابت همراه با Manifest.
- آزمون‌های Regression برای Data Race، Pongهای نامرتب، Packet Loss پیوسته، تکرار مذاکره در فقدان پاسخ و تست‌های `go test -race`.

**محدودیت مهم:** پروتکل ICMP همچنان نشانگرهای Wire v4 را دارد. برای جلوگیری از شکستن سازگاری، قالب شبکه تغییر نکرده است. این نسخه تضمین بی‌وقفه‌بودن اتصال یا عدم شناسایی ICMP نیست و آزمون عملی دو VPS هنوز لازم است.

## [3.2.0](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.0) — امنیت و پایداری نشست

**Config schema: 3 · Secure wire: 4 · Linux: AMD64 / ARM64**

### بهبودها / Improvements

- **مقاوم‌سازی مذاکره مجدد:** درخواست ClientHello قدیمی و معتبرِ ضبط‌شده، به‌تنهایی نشست فعال را بازنشانی نمی‌کند. کلید جدید در نشست کاندید مذاکره و پس از اثبات X25519 جایگزین می‌شود.
- **Smart Recovery:** صف موقت داده تا سقف **256 بسته / 2 MiB / 12 ثانیه**؛ شمارش بسته‌های حذف‌شده در زمان انقضا و پرشدن صف.
- **مدیریت خطا:** خروج غیرصفر از هسته Go در خطاهای راه‌اندازی، برای عملکرد درست `systemd Restart=on-failure`.
- **پایش امنیتی:** فرمان `pingtunnel security` و گزارش خصوصی نشست امن، Replay، خطای احراز هویت و بازیابی.
- **همخوانی نسخه‌ها:** Release نسخه‌دار، SHA256، فایل Manifest و کنترل هم‌نسخه‌بودن Rust Manager و Go Core هنگام نصب.
- **تمیزکاری:** حذف ابزار Python قدیمی از مخزن و جلوگیری از نمایش مکرر کلید ذخیره‌شده در Setup.
- **تست‌های رگرسیون:** آزمون‌های بازپخش پیام کنترلی، مذاکره کلید جدید، صف‌بندی محدود و خروج ناموفق فرمان‌ها.

### سازگاری / Compatibility

فایل تنظیمات **schema 3** و کلید جفت‌سازی حفظ می‌شوند. قالب ارتباط **Wire v4** است و با 3.1 در سطح پروتکل سازگار است. Restart سرویس همچنان می‌تواند نشست‌های فعال را قطع کند.

## [3.1.0](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/rust-latest) — امنیت نشست و Forward Secrecy

**Config schema: 3 · Secure wire: 4**

- توافق کلید موقت **X25519** با احراز هویت مبتنی بر کلید مشترک و استخراج کلیدهای نشست توسط HKDF-SHA256.
- تفکیک کلیدهای ارسال/دریافت در دو جهت فیزیکی ایران→خارج و خارج→ایران.
- پیاده‌سازی ضدبازپخش داده با شماره توالی ۶۴ بیتی احرازشده و پنجره **1024 بسته**.
- شروع **Smart Recovery** با مذاکرهٔ مجدد نشست در شرایط سکوت طولانی و تقاضای فعال.
- جلوگیری از کاهش خودکار امنیت به فریم قدیمی.

**تغییر ناسازگار:** Wire v4 با پروتکل ارتباطی نسخه **3.0.0** سازگار نیست؛ هر دو VPS باید به یک خانوادهٔ Wire سازگار ارتقا یابند.

> لینک `rust-latest` یک انتشار rolling است و لزوماً نسخه تاریخی 3.1 را نمایش نمی‌دهد. برای دریافت فعلی از انتشار ثابت **3.2.0** استفاده کن.

## 3.0.0 — راه‌اندازی یکپارچه و کلید جفت‌سازی

**Config schema: 3 · Wire: earlier PTA1 format**

- یک Setup واحد با **پنج سؤال** در هر VPS؛ حذف تقسیم‌بندی Easy/Advanced.
- تعیین نقش فیزیکی **Iran/Foreign**، IP سرور مقابل، نوع ترافیک TCP/UDP و **پورت مستقل همان VPS**.
- تولید کلید جفت‌سازی تصادفی **256 بیتی** در سرور خارج و ورود همان کلید در سرور ایران.
- جداسازی هویت فیزیکی VPS از نقش آغازکننده ICMP، برای پشتیبانی معماری توسعه‌های آینده؛ **تونل معکوس هنوز پیاده‌سازی نشده**.
- تعیین اجباری مقصد روی VPS خارج به شکل `127.0.0.1:PORT` و کنترل IPv4 همتای مجاز.
- رد قالب‌های تنظیمات قدیمی؛ مهاجرت خودکار از نسخه‌های قبل از 3.0 انجام نمی‌شود.

## سیاست نگهداری / Release policy

- **Config schema** با تغییرات معمول امنیتی و قابلیت‌های داخلی خودکار شکسته نمی‌شود. قالب معتبر فعلی `schema_version=3` است.
- **Wire compatibility** از schema جداست. هر تغییر ناسازگار در پروتکل باید شماره Wire مناسب و مسیر ارتقای هماهنگ/بدون کاهش امنیت داشته باشد.
- باینری‌های **Go Core** و **Rust Manager** باید به‌صورت یک مجموعه منطبق منتشر شوند و نصب‌کننده قبل از جایگزینی فایل‌های فعلی، صحت آن‌ها را بررسی کند.
- انتشارهای GitHub و موفقیت CI **جایگزین آزمایش روی دو VPS واقعی یا ممیزی رمزنگاری مستقل نیستند**.
- درباره نسخه‌های قبل از 3.0 به [تاریخچه Git](https://github.com/MSMSofts/MSM-Pingtunnel/commits/main/) مراجعه کن؛ مهاجرت از آن‌ها به‌صورت خودکار پشتیبانی نمی‌شود.
