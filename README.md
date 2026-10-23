# Pingtunnel Manager

مدیریت و نصب آسان [Pingtunnel](https://github.com/esrrhs/pingtunnel) در لینوکس، با منوی تعاملی، مدیریت سرویس `systemd` و نمایش لاگ‌ها.

> این مخزن بر پایهٔ Pingtunnel Manager اولیه است و مسیرهای نصب و به‌روزرسانی به **meysamrn/Pingtunnel_manager** منتقل شده‌اند. پروژهٔ اصلی انتقال ICMP، [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel) است.

## نصب سریع روی Ubuntu / Debian

روی هر سرور، این دو دستور را اجرا کنید. می‌توانید اسکریپت دانلودشده را پیش از اجرا بررسی کنید:

~~~bash
curl -fsSL https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
~~~

نصب‌کننده با `apt-get` بسته‌های `python3`، `python3-colorama`، `curl` و `ca-certificates` را نصب می‌کند، کد Manager را در `/usr/local/bin/install_pingtunnel.py` قرار می‌دهد و باینری متناسب با معماری را از [انتشارهای رسمی Pingtunnel](https://github.com/esrrhs/pingtunnel/releases) دریافت می‌کند. فایل‌های نصب در `/opt/pingtunnel` قرار می‌گیرند.

**پیش‌نیازها:** توزیع Ubuntu/Debian با `apt-get`، Python 3.8 یا جدیدتر، دسترسی `sudo`، اینترنت، و برای مدیریت سرویس، `systemd`. معماری‌های تعریف‌شده: `x86_64`، `aarch64/arm64`، `armv6l/armv7l` و `i386/i686`. هنوز تست نصب انتهابه‌انتها روی تمامی نسخه‌های لینوکس انجام نشده است.

## تنظیم اولیه

1. در مرحلهٔ `Type` نقش `server` را برای سرور و `client` را برای سمت متصل‌شونده انتخاب کنید.
2. در هر دو سمت از **کلید عددی یکسان** در محدودهٔ `0` تا `2147483647` استفاده کنید. مقدار پیش‌فرض `123456` فقط نمونه است؛ برای استفادهٔ واقعی آن را تغییر دهید.
3. در سمت کلاینت، `l_port` و آدرس IP یا دامنهٔ سرور را تعیین کنید. مقدار `tcp=1` برای TCP و `tcp=0` برای UDP است.
4. تنظیمات در `/opt/pingtunnel/conf/config.json` ذخیره می‌شود. اگر autostart را فعال نکردید، با `sudo pingtunnel start` سرویس را شروع کنید.
5. `sudo pingtunnel status` و `sudo pingtunnel logs 100` را در دو سمت بررسی کنید. شبکه/فایروال نیز باید ICMP موردنیاز را عبور دهد.

> **محدودیت نسخهٔ مبنا:** مقصد `-t` در کلاینت به شکل `server:l_port` ساخته می‌شود و تنظیم مقصد سفارشی از طریق منوی فعلی وجود ندارد. این نسخه تمام گزینه‌های Pingtunnel اصلی (مانند SOCKS5) را در منو پیاده‌سازی نکرده است؛ برای چنین سناریوهایی باید `build_args` تغییر کند.

## فرمان‌ها

~~~bash
sudo pingtunnel             # منوی مدیریتی
sudo pingtunnel start       # اجرا
sudo pingtunnel stop        # توقف
sudo pingtunnel restart     # راه‌اندازی مجدد
sudo pingtunnel status      # وضعیت
sudo pingtunnel logs 100    # صد خط آخر لاگ
sudo pingtunnel edit        # ویرایش تنظیمات (نیازمند EDITOR مانند nano)
sudo pingtunnel update      # نصب آخرین نسخه از همین مخزن، با حفظ config
sudo pingtunnel uninstall   # حذف برنامه، تنظیمات و لاگ‌ها
~~~

برای بازگشت به منوی نصب و حذف:

~~~bash
sudo python3 /usr/local/bin/install_pingtunnel.py
~~~

اسکریپت‌های قدیمی `Source/bash.sh` و `Source/bash2.sh` برای سازگاری حفظ شده‌اند؛ مسیر نصب پیشنهادی `Source/install.sh` است.

## عیب‌یابی

~~~bash
sudo systemctl status pingtunnel.service --no-pager
sudo journalctl -u pingtunnel.service -n 100 --no-pager
sudo tail -n 100 /var/log/pingtunnel/pingtunnel.log
~~~

- اگر باینری دانلود نشد، دسترسی به GitHub و [Releaseهای اصلی](https://github.com/esrrhs/pingtunnel/releases) را بررسی کنید.
- صرف نصب سرویس، اتصال تونل را تضمین نمی‌کند؛ ICMP باید در مسیر مجاز باشد.
- نصب مجدد و به‌روزرسانی، فایل تنظیمات فعلی را حفظ می‌کنند. `uninstall` تنظیمات و لاگ‌ها را هم پاک می‌کند؛ از `config.json` پشتیبان بگیرید.
- اجرای اسکریپت از اینترنت با `root` خطر دارد؛ قبل از اجرا محتوای اسکریپت را بررسی کنید. باینری از انتشار اصلی Pingtunnel دریافت می‌شود ولی SHA256/امضای آن هنوز به‌طور خودکار تأیید نمی‌شود.

## English quick start

On Ubuntu/Debian, run the two commands above with sudo. Choose `server` or `client`, configure a matching numeric key and ensure required ICMP traffic is allowed. The manager runs with `sudo pingtunnel`; use `sudo pingtunnel status` to check it. The current baseline client target is generated as `server:local-port` and is not a configurable arbitrary destination.

## Credits & License

- Core tool: [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel)
- Original Manager code and attribution: [hoseinlolready/Pingtunnel_manager](https://github.com/hoseinlolready/Pingtunnel_manager)
- Manager source license: [Apache-2.0](LICENSE); the upstream Pingtunnel binary has its own license.
