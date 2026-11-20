# AutoSSL اصلاح‌شده

این ابزار مستقل از هستهٔ Pingtunnel است و روی لینوکسِ دارای **systemd**، گواهی رایگان **Let's Encrypt** را با `acme.sh` صادر و به‌صورت خودکار تمدید می‌کند.

## تفاوت‌ها با نسخهٔ اصلی
- نصب نسخهٔ **3.1.7** از acme.sh با بررسی شناسهٔ تگ و **امضای دیجیتال انتشار**؛ بدون اجرای مستقیم `curl | sh`.
- عدم ساخت ایمیل جعلی، عدم استفاده از `--force`، بررسی ورودی‌ها و توقف در خطا.
- پشتیبانی از دو روش **standalone** و **webroot** برای جلوگیری از تداخل با وب‌سرورِ فعال.
- ذخیرهٔ کلید خصوصی در مسیر حفاظت‌شده و استفاده از مسیر ثابت برای فایل‌های گواهی.
- تمدید روزانه با **systemd timer** و بازیابی اجرای از‌دست‌رفته، همراه با اجرای reload فقط برای سرویس معرفی‌شده.
- گزارش سلامت، وضعیت گواهی، قفل هم‌زمانی، تست CI و گزارش مشکلات رفع‌شده.

## نصب روی Ubuntu / Debian

```bash
git clone https://github.com/MSMSofts/MSM-Pingtunnel.git
cd MSM-Pingtunnel
sudo bash tools/autossl/autossl.sh install --email admin@example.com --install-deps
```

ایمیل نمونه را **حتماً با ایمیل واقعی خودتان** جایگزین کنید. پارامتر `--install-deps` نصب بسته‌های سیستم را مجاز می‌کند و در صورت وجود وابستگی‌ها می‌توان آن را حذف کرد.

## دریافت گواهی

اگر پورت ۸۰ TCP آزاد است و از اینترنت به سرور می‌رسد:

```bash
sudo autossl issue --domain sub.example.com --challenge standalone
```

اگر Nginx/Apache روی پورت ۸۰ فعال است و مسیر `/.well-known/acme-challenge/` را از webroot مشخص سرو می‌کند:

```bash
sudo autossl issue --domain sub.example.com --challenge webroot --webroot /var/www/html --reload-service nginx
```

**نکته:** برای صدور و تمدید روش HTTP-01، دامنه باید از اینترنت قابل‌دسترسی باشد. در حالت standalone پورت ۸۰ باید هنگام **هر تمدید** آزاد باشد؛ اسکریپت سرویس دیگری را خودکار متوقف نمی‌کند.

فایل‌ها در مسیرهای زیر تولید می‌شوند:

```text
/etc/autossl/certs/sub.example.com/private.pem
/etc/autossl/certs/sub.example.com/fullchain.pem
```

سرویس مصرف‌کننده باید جداگانه به این دو مسیر تنظیم شود. گزینهٔ `--reload-service` فقط سرویس مشخص‌شده را reload می‌کند؛ بدون این گزینه هیچ سرویسی Restart/Reload نمی‌شود.

## دستورات مدیریت

```bash
sudo autossl doctor --domain sub.example.com
sudo autossl status --domain sub.example.com
sudo autossl renew
systemctl list-timers autossl-renew.timer
journalctl -u autossl-renew.service -n 100 --no-pager
```

## محدودیت‌ها و ایمنی

این نسخه نیازمند systemd و دسترسی root است و DNS-01، گواهی wildcard، تنظیم خودکار فایروال یا پیکربندی خودکار Nginx را انجام نمی‌دهد. تست‌های مخزن فقط سناریوهای شبیه‌سازی‌شده را می‌سنجند؛ قبل از استفادهٔ عملیاتی، روی دامنه و سرور آزمایشی صدور و تمدید واقعی را کنترل کنید. کلید خصوصی را عمومی یا world-readable نکنید.

[راهنمای انگلیسی](README.md) · [گزارش مشکلات و اصلاحات](ISSUES.md) · [مجوز و کد اصلی](upstream/)
