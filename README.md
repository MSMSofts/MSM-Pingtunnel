# Pingtunnel Manager 2.4 — یک سرور ایران + یک سرور خارج

مدیر سبک و یکپارچهٔ [Pingtunnel](https://github.com/esrrhs/pingtunnel) برای **فقط دو VPS**: ایران نقش `Client` دارد و خارج نقش `Server`. هسته تونل همچنان **Go** است؛ Rust فقط برای منو و مدیریت systemd استفاده می‌شود. ترافیک بین دو سرور از ICMP عبور می‌کند.

**HA و سرور پشتیبان، Multi-Endpoint، انتخاب مسیر خودکار و قابلیت‌های وابسته به آن از این نسخه حذف شده‌اند.** برای پایداری، `systemd` در صورت توقف غیرمنتظره هسته Go آن را دوباره راه‌اندازی می‌کند. در این معماری مسیر جایگزین نداریم و قطع شبکه لزوماً بدون وقفه قابل جبران نیست.

## نصب یک‌خطی (روی هر دو VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/install.sh -o /tmp/pingtunnel-install.sh && sudo bash /tmp/pingtunnel-install.sh
```

پیش‌نیاز: Ubuntu/Debian دارای systemd، دسترسی sudo/root و امکان دانلود فایل‌ها از GitHub. فایل نصب را می‌توان [پیش از اجرا بررسی کرد](Source/install.sh).

پس از نصب، **فقط** دستور زیر را اجرا کن:

```bash
pingtunnel
```

منو از کاربر عادی در صورت نیاز دسترسی sudo می‌گیرد. برای بار اول گزینهٔ **6 — Easy setup** را انتخاب کن.

## راه‌اندازی اولین بار

**در VPS خارج:** از منو `Easy setup` و سپس `1) Foreign Server` را انتخاب کن. برنامه یک کلید عددی جدید تصادفی تولید می‌کند. کلید را به‌صورت امن به سرور ایران منتقل کن.

**در VPS ایران:** `Easy setup` و سپس `2) Iran Client` را انتخاب کن. فقط آدرس IP/DNS سرور خارج، کلید تولیدشده و مقصد واقعی سرویس در سمت خارج، یعنی `host:port` را وارد کن. آدرس مقصد باید حقیقتاً روی سمت خارج دسترس‌پذیر باشد.

به‌طور پیش‌فرض پورت محلی ایران `4455` و نوع ترافیک سرویس TCP است. از منو می‌توان UDP را هم انتخاب کرد. **انتخاب UDP فقط مربوط به ترافیک منتقل‌شده است؛ خود تونل همچنان ICMP است.**

به‌جز این اطلاعات ضروری، نصب وابستگی‌ها، آماده‌سازی سرویس، اجرای خودکار هنگام بوت، ذخیره تغییرات و بازیابی پس از توقف پردازش با سیستم انجام می‌شود. برنامه نمی‌تواند IP سرور دیگر، کلید ازپیش‌مشترک یا مقصد واقعی را بدون اطلاع کاربر حدس بزند.

## منوی کامل

| گزینه | قابلیت |
| --- | --- |
| 1–5 | وضعیت، شروع، توقف، راه‌اندازی مجدد و لاگ |
| 6 | راه‌اندازی آسان ایران ↔ خارج |
| 7 | تنظیمات پیشرفته Client/Server |
| 8 | انتخاب TCP یا UDP برای ترافیک |
| 9 | اعتبارسنجی تنظیمات |
| 10 | آپدیت Manager |
| 11 | حذف برنامه با تأیید |
| 12 | ویرایش تخصصی JSON و اعمال خودکار |
| 13 | خروج |

تنظیمات منو بعد از ذخیره، به‌صورت خودکار با systemd هماهنگ و اعمال می‌شوند. نیازی نیست `service-install` و `restart` را جداگانه اجرا کنی.

## ارتقا از نسخه‌های دارای HA

نصب‌کننده 2.4 به‌صورت خودکار بخش قدیمی `ha` را از تنظیمات حذف می‌کند و با حفظ نقش Client/Server، **آدرس سرور اصلی، کلید، مقصد، پورت، حالت TCP/UDP و autostart** سرویس تک‌مسیره را راه‌اندازی می‌کند. فایل تنظیمات قدیمی قبل از مهاجرت در این مسیر نگهداری می‌شود:

```text
/opt/pingtunnel/conf/config.json.before-single-route.bak
```

نصب‌کننده همچنین در صورت شکست ارتقا می‌کوشد تنظیمات و سرویس قبلی را بازگرداند. فایل‌های اجراکننده HA از کد اصلی مخزن حذف شده‌اند و سرویس systemd جدید مستقیماً هسته Go را اجرا می‌کند. **ارتقای سرویس فعال ممکن است یک وقفهٔ کوتاه ایجاد کند.** پیش از نصب روی سرور عملیاتی، بهتر است جداگانه از کانفیگ بکاپ بگیری.

## وضعیت سرویس و عیب‌یابی

```bash
pingtunnel
sudo systemctl status pingtunnel.service --no-pager
sudo journalctl -u pingtunnel.service -n 100 --no-pager
sudo systemctl show pingtunnel.service -p MainPID -p MemoryCurrent -p NRestarts
```

فایل تنظیمات: `/opt/pingtunnel/conf/config.json` (مجوز 0600). هسته Go در `/opt/pingtunnel/bin/pingtunnel` و فرمان مدیریتی در `/usr/local/bin/pingtunnel` نصب می‌شوند.

## توسعه

```bash
cd Rust
cargo test
cargo build --release
```

GitHub Actions تست‌ها و نسخه‌های استاتیک `linux/amd64` و `linux/arm64` را می‌سازد و [Release](https://github.com/meysamrn/Pingtunnel_manager/releases/tag/rust-latest) را منتشر می‌کند. تست عملی عبور ICMP بین دو VPS و صحت مقصد باید روی خود سرورها تأیید شود.

Credits: [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel) برای هسته Go، [hoseinlolready/Pingtunnel_manager](https://github.com/hoseinlolready/Pingtunnel_manager) برای Manager اولیه. مجوز Manager: [Apache-2.0](LICENSE).
