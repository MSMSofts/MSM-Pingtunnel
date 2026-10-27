# Changelog / تاریخچه تغییرات

## [3.3.1](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.1) — تطبیق Poll معکوس با بار واقعی و بازیابی صف

**Config schema: 3 · Secure wire: 4 · No new external packet framing**

- The overseas VPS now uses an **event-driven adaptive timer** rather than waking every 2 ms while idle. The nominal reverse polling delay is **200 ms during handshake / 250 ms idle / 80 ms during quiet active connections / 40 ms after one useful authenticated data frame / 12 ms after a small burst / 2 ms during sustained throughput**. Poll intervals are load-aware, not network congestion guarantees.
- Multiple useful authenticated frames must arrive in a short period before moving to the fastest 2 ms polling cadence; an isolated datagram can no longer trigger hundreds of speculative polls per second.
- The Iran server no longer generates a **redundant userspace empty Echo Reply** for idle polls. Existing kernel Echo behavior remains under host control. Encrypted queued application frames still receive explicit matching Echo Replies.
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
