# Pingtunnel Manager — Rust edition

**مدیر کم‌مصرف برای [Pingtunnel](https://github.com/esrrhs/pingtunnel)، مستقل از Python در زمان اجرا.**

در این نسخه، رابط مدیریتی Rust فقط برای تنظیمات و کنترل سرویس اجرا می‌شود. فرمان `run` با `exec()` پردازش خودش را جایگزین هسته Go می‌کند و `systemd` مسئول Restart، محدودیت حافظه و ثبت لاگ است. **هیچ فرایند مدیریت Python یا Rust به‌طور دائمی در کنار هسته Go اجرا نمی‌شود.** این تغییر به‌تنهایی سرعت انتقال ترافیک ICMP را افزایش نمی‌دهد.

## نصب سریع — Ubuntu/Debian با systemd

```bash
curl -fsSL https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/install.sh -o /tmp/pingtunnel-install.sh
less /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
```

نصب‌کننده برای CPUهای x86_64 و aarch64 ابتدا باینری استاتیک Rust را از [GitHub Releases](https://github.com/meysamrn/Pingtunnel_manager/releases) و فایل SHA256 آن دریافت می‌کند. در صورت نبود Release، روی Debian/Ubuntu از source با Cargo کامپایل می‌کند؛ این مرحله روی VPS ضعیف می‌تواند سنگین باشد. برای ممنوع‌کردن کامپایل:

```bash
sudo env PINGTUNNEL_NO_COMPILE=1 bash /tmp/pingtunnel-install.sh
```

باینری Go اصلی از [نسخه‌های رسمی esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel/releases) دانلود می‌شود، فقط اگر هنوز نصب نشده باشد. برای دانلود مجدد آخرین نسخه هسته:

```bash
sudo env PINGTUNNEL_REFRESH_GO=1 bash /tmp/pingtunnel-install.sh
```

**ارتقا از نسخه Python:** فایل `/opt/pingtunnel/conf/config.json` حفظ می‌شود. کلیدهای `type`, `key`, `server`, `l_port`, `tcp`, `memory_mb`, `autostart` پشتیبانی می‌شوند. ابتدا از فایل تنظیمات نسخه پشتیبان بگیرید. نصب‌کننده در صورت شکست پس از مرحلهٔ جایگزینی، برای بازگرداندن باینری‌ها و فایل‌های سرویس تلاش می‌کند.

## دستورات

```bash
sudo pingtunnel                  # منوی تعاملی
sudo pingtunnel configure        # تنظیم server/client و پورت‌ها
sudo pingtunnel validate         # بررسی کانفیگ بدون تغییر
sudo pingtunnel dry-run          # فرمان Go (کلید مخفی)
sudo pingtunnel service-install  # ساخت واحد systemd و MemoryMax
sudo pingtunnel start
sudo pingtunnel stop
sudo pingtunnel restart
sudo pingtunnel status
sudo pingtunnel logs 100
sudo pingtunnel edit
sudo pingtunnel update
sudo pingtunnel uninstall        # حفظ config و logs
sudo pingtunnel uninstall --purge # پاکسازی کامل
```

در کلاینت، `server` سرور Pingtunnel، `l_port` پورت گوش‌دادن محلی و `target` مقصد واقعی `host:port` است؛ مثلاً `127.0.0.1:22`. برای سازگاری اگر `target` در تنظیمات قدیمی نباشد مانند قبل `server:l_port` استفاده می‌شود. `tcp=1` برای TCP و `tcp=0` برای UDP است. شبکه باید عبور ICMP موردنیاز را مجاز بداند.

فایل‌های مهم: `/opt/pingtunnel/conf/config.json` (با دسترسی 0600)، `/opt/pingtunnel/bin/pingtunnel` (هسته)، `/usr/local/bin/pingtunnel` (Rust) و `/etc/systemd/system/pingtunnel.service`.

## مصرف منابع و عیب‌یابی

```bash
sudo systemctl status pingtunnel.service --no-pager
sudo journalctl -u pingtunnel.service -n 100 --no-pager
sudo systemctl show pingtunnel.service -p MainPID -p MemoryCurrent -p NRestarts
```

`memory_mb` سقف مصرف سرویس را به `MemoryMax=` تبدیل می‌کند؛ 0 یعنی بدون سقف تعیین‌شده از طرف Manager. پیش از نتیجه‌گیری درباره درصد صرفه‌جویی RAM یا افزایش سرعت، روی VPS خود بنچمارک بگیرید.

## توسعه و Build

کد Rust در `Rust/src/main.rs` و تست‌های سازگاری تنظیمات در همان فایل هستند. GitHub Actions روی Pull Request تست می‌کند و پس از موفقیت نسخه اصلی روی `main` فایل‌های Linux amd64/arm64 (musl static) را در Release شناور `rust-latest` منتشر می‌کند.

```bash
cd Rust
cargo test
cargo build --release
```

نسخه Rust برای مدیریت سرویس به Linux + systemd نیاز دارد. فایل `Source/Pingtunnel.py` برای مشاهده کد قدیمی نگهداری شده ولی به‌عنوان Runner استفاده نمی‌شود. SHA256 تنها یک بررسی تمامیت است، نه تأیید مستقل زنجیره تأمین. اسکریپتی را که با root اجرا می‌کنید ابتدا بازبینی کنید.

**Credits:** [Go core by esrrhs](https://github.com/esrrhs/pingtunnel)؛ [Original Python manager](https://github.com/hoseinlolready/Pingtunnel_manager). [Apache-2.0 license](LICENSE) برای این Manager؛ هسته مجوز خودش را دارد.

## High Availability (HA) — Make-before-break TCP failover

این قابلیت برای کاربران ایران/خارج به‌صورت **اختیاری** اضافه شده است. نوع هسته Go عوض نمی‌شود.

**محدودیت فنی بسیار مهم:** این حالت بین دو یا چند سرور **خارج** که هرکدام Pingtunnel Server هستند جابه‌جا می‌شود؛ «تونل معکوس» را پیاده‌سازی نمی‌کند. یک اتصال TCP فعال روی سرور قدیمی نگه داشته می‌شود و فقط اتصال‌های **جدید** به سرور بهتر می‌روند. اگر مسیر قبلی ناگهان قطع شود، نشست‌های TCP آن مسیر قابل انتقال زنده به مسیر دیگر نیستند و اتصال مجدد برنامهٔ کاربر لازم است. UDP و SOCKS5 و جابه‌جایی reverse در این نسخه HA پشتیبانی نمی‌شود.

### پیش‌نیاز

1. در ایران: Pingtunnel Client در حالت TCP (`type=client`, `tcp=1`) با پورت محلی ثابت.
2. در خارج: دست‌کم **دو Pingtunnel Server مستقل** با کلید عددی مشترک و امکان دسترسی به یک مقصد TCP مشترک.
3. در هر دو مقصد خارج، اتصال HTTPS به `1.1.1.1:443` برای Health Probe پیش‌فرض برقرار باشد (یا `ha.probe_target` و `ha.probe_domain` را مطابق یک سرور HTTPS معتبر خودتان تنظیم کنید).
4. VPS ایران باید RAM کافی برای دو نمونهٔ هسته داده + دو نمونهٔ هسته تست سلامت و پردازش Rust proxy داشته باشد. پیش از فعال‌سازی روی سرور اصلی، تست واقعی انجام دهید.

### راه‌اندازی HA روی سرور ایران

پس از نصب نسخه جدید و انجام `sudo pingtunnel configure` برای تونل مستقیم:

```bash
sudo pingtunnel ha-setup           # IP سرور خارج دوم را وارد کنید
sudo pingtunnel validate
sudo pingtunnel service-install
sudo pingtunnel restart
sudo pingtunnel ha-status
sudo pingtunnel logs 100
```

**توجه:** سرویس برای شروع HA باید یک بار restart شود و در همان مرحله انتقال اولیه ممکن است اتصال‌ها قطع شوند. پس از فعال‌شدن HA، تغییر *خودکار مسیر* در همان اجرای سرویس، اتصال‌های سالمِ موجود را روی مسیر قبلی حفظ می‌کند.

برای بازگشت به حالت تک‌مسیره، مقدار `ha.enabled` را در `/opt/pingtunnel/conf/config.json` به `false` تغییر دهید، سپس `service-install` و `restart` را اجرا کنید.

### مثال تنظیمات پیشرفته

این بخش را به تنظیمات **Client** فعلی اضافه کنید و IPها را با مقادیر واقعی جایگزین کنید:

```json
{
  "type": "client",
  "key": "123456",
  "tcp": 1,
  "l_port": 4455,
  "server": "203.0.113.10",
  "target": "10.0.0.5:443",
  "autostart": true,
  "memory_mb": 0,
  "ha": {
    "enabled": true,
    "listen_host": "127.0.0.1",
    "endpoints": [
      {"name": "foreign-a", "server": "203.0.113.10"},
      {"name": "foreign-b", "server": "198.51.100.20"}
    ],
    "data_port_base": 36000,
    "probe_port_base": 37000,
    "probe_enabled": true,
    "probe_target": "1.1.1.1:443",
    "probe_domain": "one.one.one.one",
    "check_seconds": 10,
    "failure_threshold": 2,
    "success_threshold": 2,
    "switch_streak": 3,
    "cooldown_seconds": 120,
    "max_connections": 256
  }
}
```

آدرس‌ها در مثال **آزمایشی و غیرقابل استفاده واقعی** هستند. برای سازگاری با نصب‌های فعلی، دستور `ha-setup` درگاه عمومی `0.0.0.0:l_port` را حفظ می‌کند. در تنظیم دستی می‌توانید `listen_host=127.0.0.1` قرار دهید تا دسترسی محدود به خود سرور شود. داخلی‌ها روی `127.0.0.1:36000..` و پروب‌ها روی `127.0.0.1:37000..` فعال می‌شوند و نباید با پورت‌های برنامه‌های دیگر تداخل داشته باشند.

**مکانیسم انتخاب:** هر ۱۰ ثانیه نمونه‌ای از تبادل HTTPS واقعی از داخل ICMP انجام می‌شود؛ بعد از دو موفقیت مسیر سالم و بعد از دو شکست متوالی ناسالم ارزیابی می‌شود. انتقال اضطراری به مسیر سالم بدون درنظرگرفتن cooldown انجام می‌شود. برای انتخاب مسیر بهتر از نظر تأخیر، بهبود معنادار پایدار، ۳ اندازه‌گیری متوالی و حداقل ۱۲۰ ثانیه فاصله از آخرین تغییر لازم است. به این ترتیب نوسان‌های جزئی موجب تغییر پیاپی مسیر نمی‌شوند. این الگوریتم توان عملیاتی را اندازه نمی‌گیرد و صرفاً کیفیت probe را مقایسه می‌کند.

**حریم خصوصی و امنیت:** فایل‌های اجرای هسته در `/run/pingtunnel-ha` با مجوز `0600` تولید می‌شوند تا کلید در فهرست آرگومان‌ها قرار نگیرد. دسترسی به فایل وضعیت `/run/pingtunnel-ha/status.json` نیز به root محدود است. برای استفاده امن‌تر، پورت ورودی HA را فقط به شبکه مجاز محدود کنید.

در صورت خاموش‌بودن HA، همچنان همان معماری کم‌مصرف قبلی با `exec` و بدون پردازش مدیریتی دائمی کار می‌کند.
