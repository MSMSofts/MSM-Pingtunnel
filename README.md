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
