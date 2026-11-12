# IPCAndExtensionAuditor — run 33a85550 participant 1

রিপোর্ট: [B-ipc.md](C:\Users\Admin\AppData\Local\Temp\pv-scan\B-ipc.md)

**P0 —** `content.js:1912/2015`: `#__pv_drop` পেজ-DOM-এ fixed id, fill handler-এ `isTrusted` নেই। পেজ `input.focus()` করালে dropdown খোলে, তারপর `dispatchEvent(new MouseEvent('mousedown'))` → `fillLogin` পাসওয়ার্ড পেজের নিজের input-এ লেখে → পেজ পড়ে নেয়। ইউজার ক্লিক লাগে না।

**P0 —** `content.js:2463/2563`: badge `[data-pv-kind="shield"]`-এ `click()` দিলে একটাই ম্যাচ থাকলে `rows[0].onPick()` সরাসরি autofill করে। একই ফল, এক লাইনে।

**P1 —** `content.js:515`: `#__pv_otp_picker` `mode:"open"` shadow root, ভিতরে live TOTP কোড টেক্সট। পেজ `host.shadowRoot.textContent` পড়ে 2FA কোড নিতে পারে (`:731` row click-ও unguarded)।

**P1 —** `background.js:477/519/533/543`: `PV_QUERY`/`PV_LIST`/`PV_FETCH`/`PV_TOTP_LOOKUP`-এ কোনো sender check নেই; `all_frames:true` তাই যেকোনো iframe/content-script পুরো vault—plaintext password সহ (`native_host.rs:619`, `:1591`)—চাইতে পারে।

**P1 —** `native_host.rs:141/3371`: allow-list ফাঁকা/অনুপস্থিত হলে `origin_allowed()` true; আর argv `"native-host"` চেকটাই বাইপাস করে। ফলে লোকাল প্রসেস `phantom_vault.exe native-host` চালিয়ে unlocked অবস্থায় stdout-এ পুরো vault পায়।

Verified good: framing-এ 1 MiB cap + `read_exact` (DoS নেই), প্রতি frame-এ unlock গেট, API `127.0.0.1:0` + header-only bearer[redacted] + constant-time, XSS নেই (সব vault string `textContent`), hook.js data-free, `externally_connectable` নেই।