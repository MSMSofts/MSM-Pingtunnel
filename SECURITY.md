# Security Policy / سیاست امنیتی

[README فارسی](README.md) · [English README](README.en.md) · [معماری فنی](docs/ARCHITECTURE.md)

## سیاست امنیتی

**Pingtunnel Manager 3.2.1** یک پروتکل انتقال ICMP با رمزنگاری احرازشده و توافق کلید موقت دارد. این پیاده‌سازی **ممیزی رمزنگاری مستقل عمومی نشده است** و ادعای ناشناس‌بودن ICMP، عبور قطعی از فیلترینگ یا مقاومت کامل در برابر حملات حجمی ندارد.

### نسخه‌های پشتیبانی‌شده

| نسخه | وضعیت |
| --- | --- |
| **3.2.1** | جدیدترین نسخه؛ اصلاح Data Race و سلامت سرویس |
| **3.2.0** | نسخه قبلی Wire v4؛ ارتقا توصیه می‌شود |
| **3.1.0** | پروتکل Wire v4؛ ارتقا به 3.2 توصیه می‌شود |
| **3.0.0** | پروتکل قدیمی؛ ارتباط مستقیم با 3.1/3.2 برقرار نمی‌شود |
| **قبل از 3.0** | فرمت قدیمی؛ بدون مهاجرت خودکار |

### چه چیزی حفاظت می‌شود؟

- محرمانگی و تمامیت داده‌های تونل میان یک VPS ایران و یک VPS خارج.
- احراز هویت همتای دارای کلید جفت‌سازی مشترک.
- جلوگیری از پذیرش داده‌های تغییر‌یافته یا بازپخش‌شده، با شماره توالی ۶۴ بیتی و پنجرهٔ ۱۰۲۴ بسته.
- جداسازی کلیدهای نشست برای جهت‌های ایران→خارج و خارج→ایران.
- محدودسازی مقصد خروجی سرور خارج به `127.0.0.1:PORT` و کنترل IPv4 مبدأ مجاز.

**مکانیزم‌ها:** کلید جفت‌سازی تصادفی ۲۵۶ بیتی، توافق کلید موقت X25519 با احراز هویت PSK، HKDF-SHA256 و انتخاب خودکار AES-256-GCM یا XChaCha20-Poly1305. مذاکرهٔ مجدد به‌صورت مرحله‌ای انجام می‌شود تا یک Hello قبلیِ شناخته‌شده به‌تنهایی نشست فعال را قطع نکند.

### چه چیزی تضمین نمی‌شود؟

- **ICMP و الگوی بسته‌ها همچنان قابل مشاهده‌اند.** فریم‌های فعلی نشانگرهای ثابت `PTH4` و `PTD4` دارند؛ صرف وجود AES/XChaCha به معنی مقاومت تضمینی در برابر DPI نیست.
- از دست‌رفتن، محدودسازی سرعت، مسدودسازی ICMP یا DoS حجمی ممکن است سرویس را قطع کند.
- Forward Secrecy در سطح نشست، در برابر تصاحب حافظهٔ فرایند فعال یا افشای هم‌زمان کلیدهای نشست تضمین مستقلی ارائه نمی‌کند.
- اگر کلید جفت‌سازی فاش شود، همتای جدید ممکن است جعل شود. تعویض کلید ریشه باید روی هر دو VPS هماهنگ انجام شود؛ گردش کلید بدون وقفه هنوز وجود ندارد.
- صف محدود Smart Recovery ممکن است در قطعی‌های طولانی بسته حذف کند؛ ادامهٔ بی‌وقفهٔ تمام نشست‌های TCP/UDP تضمین نیست.
- این تونل جایگزین امنیت TLS/QUIC، احراز هویت سرویس VPN یا تنظیمات امن سرور نیست.

### حفاظت عملیاتی

- خروجی `sudo pingtunnel key` حاوی کلید حساس است؛ آن را در Issue، اسکرین‌شات یا گزارش عمومی قرار نده.
- فایل‌های `/opt/pingtunnel/conf/config.json` و `/run/pingtunnel-core.json` شامل مواد کلیدی هستند و باید فقط با دسترسی محدود نگهداری شوند.
- نسخهٔ پشتیبان از تنظیمات نیز به‌اندازهٔ اصل فایل حساس است.
- فایل‌های وضعیت `/run/pingtunnel-security.json` و `/run/pingtunnel-performance.json` برای عیب‌یابی‌اند، نه گواهی امنیت.
- در صورت امکان سرویس مقصد خارجی را در Loopback نگه دار و تنها ترافیک لازم را در فایروال مجاز کن.
- داشتن دسترسی root به VPS می‌تواند به کلید ذخیره‌شده و داده‌های نشست فعال دسترسی بدهد.

### گزارش آسیب‌پذیری

برای مواردی مانند دورزدن رمزنگاری، افشای کلید، دورزدن محدودیت مقصد یا اشکال Anti-Replay، **جزئیات قابل سوءاستفاده و اسرار را عمومی منتشر نکن**. اگر گزینهٔ *Private vulnerability reporting* در GitHub مخزن فعال باشد از همان استفاده کن؛ در غیر این صورت ابتدا از یک راه ارتباط خصوصی که نگهدارنده تأیید کرده هماهنگ شو. برای خطاهای غیرحساس از [Issues](https://github.com/MSMSofts/Pingtunnel_manager/issues) استفاده کن.

در گزارش خود نسخه Manager، نسخه Go Core، نسخه Wire، نقش VPS و مراحل بازتولید را بدون IP محرمانه، کلید واقعی یا دادهٔ خصوصی وارد کن. آزمون تهاجمی روی سرور دیگران بدون مجوز انجام نده.

---

## English security notes

Pingtunnel Manager uses a **custom authenticated ICMP transport**. Version **3.2.1** is the documented release. This project has **not been independently audited**, and encryption does **not** guarantee resistance to traffic analysis, ICMP blocking, denial of service, or endpoint compromise.

**Supported security properties:** a random 256-bit pairing root, PSK-authenticated ephemeral X25519 agreement, HKDF-SHA256 directional session keys, auto-selected AES-256-GCM/XChaCha20-Poly1305, authenticated 64-bit sequence numbers, a 1,024-packet replay window, and an overseas server policy restricting ingress peer IPv4 and the forwarding target to local loopback.

**Limitations:** ICMP is observable and the wire framing has identifiable fixed markers. Root-key compromise can enable future impersonation. Active process compromise may reveal session data. Bounded recovery buffers can lose application traffic. No automatic Direct/Reverse failover, full ICMP DoS protection or zero-downtime pairing-root rotation is provided.

**Compatibility:** config schema 3 persists across versions 3.0–3.2. Wire v4 is shared by 3.1 and 3.2, while 3.0 uses an incompatible earlier wire format; there is no silent downgrade.

**Responsible reporting:** Do not disclose exploit details or keys in public issues. Use private GitHub vulnerability reporting if enabled, or coordinate privately with the maintainer before sharing details. Non-sensitive bugs can be filed in [Issues](https://github.com/MSMSofts/Pingtunnel_manager/issues).

Evaluate security and real two-VPS ICMP reliability independently before high-assurance deployment.
