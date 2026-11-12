# راهنمای Multi-Port در MSM-Pingtunnel

## معماری

Multi-Port حداکثر ۱۲ سرویس TCP/UDP را روی یک نشست رمزنگاری‌شده و یک تونل ICMP مشترک منتقل می‌کند. هر سرویس شناسهٔ ثابت S01 تا S12، پروتکل، پورت ورودی ایران، پورت مقصد خارج و وضعیت فعال/غیرفعال دارد.

- ایران: Listener ورودی TCP یا UDP روی پورت تعیین‌شده.
- خارج: مقصد فقط `127.0.0.1:<foreign_port>` است؛ پورت مقصد را عمومی نکنید.
- TCP و UDP می‌توانند شماره پورت یکسان داشته باشند.
- هر دو VPS باید Service Profile یکسان داشته باشند.

شناسه سرویس به‌صورت Alias در فیلد احرازشدهٔ `Target` در Wire v4 منتقل می‌شود. سرور خارج Alias را با Allowlist محلی تطبیق می‌دهد و مقصد دلخواه ارسالی از همتا را قبول نمی‌کند. نسخه پروتکل و مذاکره رمزنگاری تغییر نمی‌کند.

## پیشنهادهای Wizard

در نصب تازه ۱۲ پیشنهاد قابل ویرایش نمایش داده می‌شود:

| ID | Protocol | ورودی ایران | مقصد Loopback خارج |
|---|---|---:|---:|
| S01 | TCP | 443 | 443 |
| S02 | UDP | 443 | 443 |
| S03 | TCP | 2053 | 2053 |
| S04 | UDP | 444 | 444 |
| S05 | TCP | 2083 | 2083 |
| S06 | UDP | 1194 | 1194 |
| S07 | TCP | 2087 | 2087 |
| S08 | UDP | 1701 | 1701 |
| S09 | TCP | 2096 | 2096 |
| S10 | UDP | 500 | 500 |
| S11 | TCP | 8443 | 8443 |
| S12 | UDP | 4500 | 4500 |

در نصب تازه فقط S01 (TCP) و S02 (UDP) فعال هستند و ۱۰ مورد دیگر برای جلوگیری از تداخل Listener غیرفعال‌اند. هر ردیف با قالب `protocol,iran_port,foreign_port,on/off` قابل ویرایش است. پورت‌های پیشنهادی نمونه‌اند؛ تداخل پورت‌ها را بررسی کنید. حداقل یک سرویس TCP و یک UDP باید فعال بماند.

برای نصب موجود تک‌پورتی، Wizard به‌صورت پیش‌فرض تنظیم فعلی را حفظ می‌کند. برای تبدیل، Multi-Port را صریحاً فعال کنید؛ سرویس قدیمی حفظ و یک سرویس مکمل پیشنهاد می‌شود.

## راه‌اندازی دو VPS و انتقال Profile

1. ابتدا سرور خارج را نصب و Setup کنید.
2. در Wizard پورت‌های مقصد خارج را مشخص کنید.
3. برنامه‌های مقصد باید روی `127.0.0.1:<foreign_port>` در حال اجرا باشند.
4. از خارج پروفایل را Export کنید:
   ```bash
   sudo pingtunnel services export /root/pingtunnel-services.json
   ```
5. فایل را امن به ایران منتقل کنید:
   ```bash
   scp /root/pingtunnel-services.json root@IRAN_VPS:/root/
   ```
6. در ایران Import و اعتبارسنجی کنید:
   ```bash
   sudo pingtunnel services import /root/pingtunnel-services.json
   sudo pingtunnel services check
   ```

فایل فقط شامل شناسه‌ها، پروتکل‌ها و نگاشت پورت‌هاست و Pairing Key یا Secret ندارد. پورت‌های ورودی ایران را پس از Import بررسی کنید.

## فایروال و سرویس مقصد

**ایران:** برای هر ردیف فعال، پورت ورودی را با پروتکل خودش مجاز کنید. TCP و UDP Rule جدا دارند. برای مشاهده Listenerها:

```bash
sudo ss -lntup
```

**خارج:** سرویس مقصد باید روی Loopback گوش دهد. برای مشاهده:

```bash
sudo ss -lntp
sudo ss -lnup
```

پورت‌های مقصد را عمومی نکنید. فقط ICMPv4 بین دو VPS و پورت‌های ورودی ایران را مطابق نیاز مجاز کنید. اگر پورتی در ایران اشغال باشد، Listener آن پورت Bind نمی‌شود.

## مدیریت از منو و CLI

از منوی اصلی `sudo pingtunnel` گزینهٔ **16) Multi-Port** را انتخاب کنید.

```bash
sudo pingtunnel services list
sudo pingtunnel services add
sudo pingtunnel services edit S01
sudo pingtunnel services enable S01
sudo pingtunnel services disable S01
sudo pingtunnel services remove S12
sudo pingtunnel services check
sudo pingtunnel services export /root/pingtunnel-services.json
sudo pingtunnel services import /root/pingtunnel-services.json
```

تغییر سرویس‌ها اتمیک ذخیره و با Restart کنترل‌شده اعمال می‌شوند؛ Hot Reload بدون Restart در این نسخه وجود ندارد. بعد از هر تغییر، پروفایل هر دو VPS را هماهنگ کنید.

## حفظ صف‌ها و عملکرد فعلی

این نسخه فقط Listener و Dispatcher مقصد را توسعه می‌دهد. ظرفیت و سیاست صف‌های ICMP/UDP، الگوریتم enqueue و overflow/drop، Reverse FIFO، Queue Hint، Backlog Wake، Smart Rotation، Adaptive Performance، TCP framing، congestion control، Timeout، Recovery، FEC و ICMP segmentation تغییر نمی‌کنند.

گزینه قدیمی `transport` به‌عنوان پروفایل فعلی Dispatcher/Queue حفظ می‌شود؛ در نصب تازه TCP پیش‌فرض است. هر سرویس پروتکل مستقل خودش را دارد، اما صف و زمان‌بندی همچنان مشترک و با همان سیاست قبلی است.

## محدودیت‌ها

۱۲ پورت پهنای باند ICMP را ۱۲ برابر نمی‌کند. برنامه مقصد باید روی سرور خارج نصب و فعال باشد. تست TCP به‌تنهایی سلامت UDP را اثبات نمی‌کند؛ برای UDP از تست کاربردی متناسب با سرویس استفاده کنید.
