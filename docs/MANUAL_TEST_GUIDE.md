# MANUAL TEST GUIDE — PhantomVault (non-technical friendly)

> এই ফাইলটা এমন কারও জন্য যিনি কোড জানেন না। প্রতিটা ধাপ অনুযায়ী ক্লিক করুন,
> তারপর "প্রত্যাশিত ফলাফল" মিলিয়ে দেখুন। না মিললে §2 অনুযায়ী রিপোর্ট করুন।
> ৫ বছর পরেও এই গাইড কাজ করবে — তাই এখানে তারিখ-নির্ভর কিছু নেই, শুধু
> ফিচার আর ক্লিক-পাথ আছে।
>
> Automated gates (§10) আর এই ম্যানুয়াল চেকলিস্ট (§4–§9) — দুটোই লাগবে।
> কোনো ফিচার শুধু টেস্টে পাস মানে স্ক্রিনে ঠিক — না। কোনো ফিচার শুধু স্ক্রিনে
> ঠিক মানে কোডে নিরাপদ — না।

---

## 1. যা যা লাগবে

| জিনিস | কোথায় |
|---|---|
| Windows 10 বা 11 (64-bit) | — |
| PhantomVault installer | `installer-output/PhantomVault-Setup-<version>.exe` |
| Chrome বা Edge (unpacked extension) | `browser_extension/` ফোল্ডার |
| Firefox (ঐচ্ছিক, আলাদা টেস্ট) | `browser_extension/dist/firefox/` |
| একটা খালি ফোল্ডার (ডেমো ডেটার জন্য) | যেমন `C:\pv-demo` |

> ⚠️ আসল ভল্টে টেস্ট করবেন না। §3-এর ডেমো সেটআপ ব্যবহার করুন।

---

## 2. কীভাবে ফেল রিপোর্ট করবেন

একটা ফেল রিপোর্টে এই চারটা থাকলেই যথেষ্ট:

1. **কোন ধাপ** (যেমন "§5.C ধাপ ৪")।
2. **কী আশা করেছিলেন** (গাইডের "প্রত্যাশিত" লাইনটা কপি করুন)।
3. **আসলে কী হলো** (স্ক্রিনশট বা লেখা)।
4. **কখন** (তারিখ/সময়) আর **কোন build** (`Settings → Dev & API`-তে version দেখা যায়)।

স্ক্রিনশট নেওয়ার নিয়ম: `Win + Shift + S` চাপুন, এরপর যে অংশটা দরকার
সেটা টেনে নিন। পাসওয়ার্ড বা কোড দেখা যাচ্ছে এমন স্ক্রিনশট পাঠাবেন না।

---

## 3. প্রস্তুতি (একবারই)

1. `C:\pv-demo` ফোল্ডার বানান।
2. Windows-এর Environment Variable-এ যোগ করুন: নাম `PHANTOM_VAULT_DIR`,
   মান `C:\pv-demo`. (এটা "portable mode" — সব ডেটা ওই ফোল্ডারেই থাকবে,
   তাই টেস্ট শেষে ফোল্ডারটা মুছে দিলেই সব শেষ।)
3. PhantomVault চালু করুন। প্রথমবার হলে onboarding আসবে।
4. মাস্টার পাসওয়ার্ড দিন: `Demo-Pass-123!` (শুধু ডেমোর জন্য)।
5. ভেতরে ঢুকলে বাঁ দিকের নিচে **Travel: OFF** আর **UNLOCKED · THIS DEVICE**
   দেখবেন — এটাই "ভল্ট খোলা" অবস্থা।

**রিসেট (আবার প্রথম থেকে):** PhantomVault বন্ধ করুন → `C:\pv-demo` ফোল্ডার
মুছে ফেলুন → আবার চালু করুন। এতে ডেমো ভল্ট, পেয়ারিং, cache — সব নতুন।

---

## 4. প্রথম চালু, আনলক, লক

| # | ধাপ | প্রত্যাশিত ফলাফল |
|---|---|---|
| A1 | অ্যাপ চালু করুন | Unlock স্ক্রিন, উপরে **PHANTOM VAULT**, ভাষা টগল (English / বাংলা) |
| A2 | ভুল পাসওয়ার্ড দিন | লাল error, ভল্ট খোলে না, কয়েকবার ভুল করলে অপেক্ষা বাড়ে (backoff) |
| A3 | সঠিক পাসওয়ার্ড দিন | ভল্ট খোলে, আইটেম লিস্ট দেখা যায় |
| A4 | বাঁ দিকের নিচে lock আইকনে ক্লিক করুন | ভল্ট লক হয়, unlock স্ক্রিনে ফেরে |
| A5 | আবার unlock করুন, `Ctrl+L` চাপুন | লক হয় (কীবোর্ড শর্টকাট) |
| A6 | Settings → Security → Auto-Lock | 15 মিনিট ডিফল্ট; বদলে Save করলে অ্যাপ বন্ধ করে খুললেও মানটা থাকে |
| A7 | ভাষা বাংলা করুন | মেনু, বাটন, ডায়ালগ বাংলায়; কিছু সিস্টেম-মেসেজ ইংরেজি থাকতে পারে (§11) |

---

## 5. ভল্ট ব্যবহার

### 5.A লিস্ট, সার্চ, ফিল্টার

| # | ধাপ | প্রত্যাশিত |
|---|---|---|
| A1 | উপরের সার্চ বক্সে আইটেমের নাম লিখুন | লিস্ট ফিল্টার হয়, লেখা মুছলে সব ফেরে |
| A2 | ফিল্টার চিপ: All / Favorites / Recent / Login / Card / Note / SSH / Identity / License | প্রতিটা চিপে শুধু সেই ধরনের আইটেম |
| A3 | উইন্ডো সরু করুন (~900px) | চিপগুলো দুই সারিতে ভাঁজ হয়, কিছু কাটা পড়ে না |
| A4 | বাঁ দিকে folder ড্রপডাউন বদলান | শুধু সেই ফোল্ডারের আইটেম |

### 5.B নতুন আইটেম (প্রতিটা ধরন)

প্রতিটার জন্য: **+ New Item → ধরন বাছুন → ফিল্ড ভরুন → Save**।

| ধরন | যা ভরতে হবে | প্রত্যাশিত |
|---|---|---|
| Login | title, username, password, URL | লিস্টে দেখা যায়; detail-এ পাসওয়ার্ড লুকানো, 👁 চাপলে দেখায় |
| Card | নাম, নম্বর, expiry, CVV | detail-এ কার্ড ভিউ, CVV লুকানো |
| Note | title + লেখা | লেখা অক্ষত থাকে (নতুন লাইনসহ) |
| Identity | নাম, ঠিকানা, ইত্যাদি | detail-এ গ্রুপ করা |
| SSH | নাম, public key, private key | private key masked |
| License | নাম, key, expiry | expiry তারিখ দেখায় |

**Custom field:** editor-এ **Add Custom Field** → নাম + মান + checkbox।
খালি checkbox-এ ক্লিক করলে সবুজ টিক বসে (এটা একটা আসল বাগ ছিল, এখন ঠিক)।

**Edit/Delete:** আইটেম খুলুন → Edit → কিছু বদলান → Save → বদল দেখা যায়।
Delete করলে Trash-এ যায়, Trash থেকে restore বা permanent delete করা যায়।

**Favourite:** ⭐ চাপলে Favorites চিপে চলে আসে, আবার চাপলে ফেরে।

### 5.C Password generator

1. বাঁ দিকে **Password Generator** → **Generate**।
2. প্রতিবার আলাদা পাসওয়ার্ড আসে (একই পাসওয়ার্ড দুইবার এলে ফেল)।
3. Diceware মোড বাছুন → শব্দ-ভিত্তিক পাসওয়ার্ড।
4. **Copy** চাপুন → অন্য জায়গায় paste করলে ঠিক ওটাই আসে।

### 5.D 2FA (TOTP)

1. **2FA Hub** → একটা অ্যাকাউন্ট যোগ করুন (QR স্ক্রিন/ক্যামেরা/ফাইল/ম্যানুয়াল)।
2. কোড প্রতি ৩০ সেকেন্ডে বদলায়, নিচে কাউন্টডাউন।
3. কোড কপি করে Google/Authy-র কোডের সাথে মেলান — একই হওয়া উচিত।
4. **Export** → QR গুলো paginated, প্রতিটা স্ক্যানযোগ্য।
5. ভুল QR দিলে error আসে, অ্যাপ ক্র্যাশ করে না।

### 5.E Vault Health

1. বাঁ দিকে **Security Audit** → breached / reused / weak / stale সংখ্যা দেখায়।
2. একটা row-এ ক্লিক → সেই আইটেম খোলে।
3. "breached" সংখ্যা ইন্টারনেট ছাড়া ০ বা "unknown" দেখাতে পারে — এটা ঠিক আছে।

### 5.F Master reprompt

1. একটা login-এর পাসওয়ার্ড 👁 দিয়ে দেখতে চাপুন → মাস্টার পাসওয়ার্ড চায়।
2. ভুল দিলে দেখায় না; সঠিক দিলে দেখায়।
3. একইভাবে delete/export-এও চায় (guard)।

### 5.G Auto-type / Quick Bar (ডেস্কটপ)

1. একটা লগইন সাইট খুলুন, username ফিল্ডে ক্লিক করুন।
2. অ্যাপে থাকা global hotkey চাপুন (Settings → Dev & API-তে লেখা থাকে) → **Quick Bar** আসে।
3. আইটেম বাছুন → username + password টাইপ হয়ে যায়, focus সাইটে ফেরে।
4. এমন জায়গায় (Notepad-এ কোনো ফিল্ড নেই) চাপলে — কিছুই টাইপ হয় না, কারণ দেখায়।
5. 2FA কোড থাকলে ফিল করা যায়; কাউন্টডাউন শেষ হলে টাইপ করে না।
6. অ্যাপ লক থাকলে Quick Bar কিছুই টাইপ করে না (lock = stop)।

### 5.H Attachments

1. একটা আইটেম খুলুন → attachment যোগ করুন (ছোট ফাইল)।
2. detail-এ নাম/সাইজ দেখা যায় → **Open**/**Download** কাজ করে।
3. ফাইলটা ডেস্কটপে সেভ হয়, খোলা যায়।
4. বড় ফাইল দিলে পরিষ্কার error (ক্র্যাশ নয়)।

### 5.I Secure Send (expiring note)

1. বাঁ দিকে **Secure Send** → note লিখুন, TTL দিন (যেমন ৫ মিনিট)।
2. **Seal + Publish** → একটা link/code তৈরি হয়।
3. অন্য জায়গায় (বা আবার) link দিয়ে **Read + Burn** → note দেখা যায়।
4. দ্বিতীয়বার একই link খুললে → "already read", আর দেখা যায় না।
5. TTL শেষ হলে → "expired"।

---

## 6. ব্যাকআপ, রিকভারি, ইমপোর্ট/এক্সপোর্ট

| # | ধাপ | প্রত্যাশিত |
|---|---|---|
| A1 | Settings → Backups → Backup now | একটা ফাইল তৈরি হয়, path দেখায় |
| A2 | Backup ফাইলটা অন্য ফোল্ডারে কপি করুন, তারপর Restore | আইটেম ফিরে আসে |
| A3 | Recovery Kit → print/preview | শার্ড (শব্দ/অক্ষর) দেখা যায়, প্রিন্ট হয় |
| A4 | শার্ড দিয়ে drill (restore) | সঠিক শার্ডে ভল্ট খোলে; ভুল শার্ডে খোলে না |
| A5 | Import → CSV (Chrome/Bitwarden ফরম্যাট) | preview দেখায়, প্রতিটা row Skip/Update/Import করা যায় |
| A6 | Import শেষে **Undo last import** | আগের অবস্থায় ফেরে |
| A7 | Export → `.pvx` | ফাইল তৈরি হয়; আবার import করলে আইটেম ফেরে |
| A8 | ভুল/নষ্ট ফাইল import | পরিষ্কার error, অ্যাপ ক্র্যাশ করে না |

---

## 7. সিঙ্ক (ঐচ্ছিক, ইন্টারনেট/LAN লাগে)

| # | ধাপ | প্রত্যাশিত |
|---|---|---|
| A1 | Settings → Sync & Devices → GitHub Sync | owner/repo/PAT দিয়ে Connect |
| A2 | Sync Now | "synced" status, audit log-এ entry |
| A3 | অন্য ডিভাইসে (বা অন্য ফোল্ডারে) একই repo দিয়ে sync | আইটেম merge হয় |
| A4 | দুদিকে আলাদা পরিবর্তন করে sync | **Merge Preview** দেখায়, Apply শুধু locally merge করে (জোর করে push করে না) |
| A5 | Local Wi-Fi P2P: **Enable** → অন্য ডিভাইসে কোড দেখায় | দুই ডিভাইস কোড বিনিময় করলে sync হয় |
| A6 | P2P বন্ধ থাকলে | "P2P discovery is OFF" লেখা, কোনো ক্র্যাশ নেই |

> GitHub PAT ছাড়া এই অংশ স্কিপ করা যায়। স্কিপ করলে গাইডে লিখে রাখুন।

### 7.A Duress, honeytokens, factory reset

| # | ধাপ | প্রত্যাশিত |
|---|---|---|
| A1 | Settings → Security → duress password সেট করুন (আলাদা পাসওয়ার্ড) | সেভ হয় |
| A2 | লক করে **duress** পাসওয়ার্ড দিন | ভল্ট খোলে, কিন্তু ভেতরে শুধু decoy আইটেম; আসল আইটেম নেই |
| A3 | honeytoken যোগ করুন | ভুয়া আইটেম তৈরি হয়; ব্যবহার করলে access log-এ ধরা পড়ে |
| A4 | Factory reset (DANGER ZONE) | ৩ ধাপ: পাসওয়ার্ড → `DELETE` টাইপ → ৫ সেকেন্ড কাউন্টডাউন; তারপর ভল্ট শূন্য ও onboarding ফেরে |

> Factory reset অপরিবর্তনীয় — ডেমো ভল্টে করুন, আসল ডেটায় নয়।

### 7.B Access log

1. Settings → Dev & API → **Open access log** (অথবা access log বাটন)।
2. unlock, lock, bridge install, pairing code, export — প্রতিটার একটা লাইন।
3. প্রতিটা লাইনে hash chain (`prev`/`hash`); কেউ লাইন বদলালে chain ভাঙে।
4. ফাইলে লেখা ব্যর্থ হলে উপরে "N write(s) failed this session" দেখায়।

### 7.C Travel mode

1. বাঁ দিকে নিচে **Travel: OFF** → ON করুন।
2. লক করে আবার খুলুন → Travel ON-ই থাকে।
3. OFF করলে স্বাভাবিক আচরণে ফেরে।

---

## 8. ব্রাউজার এক্সটেনশন (সবচেয়ে গুরুত্বপূর্ণ অংশ)

### 8.A ইনস্টল

1. Chrome → `chrome://extensions` → **Developer mode** চালু।
2. **Load unpacked** → `browser_extension/` ফোল্ডার বাছুন।
3. extension-এর ID কপি করুন (৩২টা ছোট হাতের অক্ষর)।
4. PhantomVault → Settings → Sync & Devices → **Browser Bridge** → ID পেস্ট →
   **Install Browser Extension Host**।
5. সফল হলে সবুজ/নীল status: "Host installed → …".
6. extension-এ reload আইকনে ক্লিক করুন।

### 8.B পেয়ারিং (নতুন, A27)

1. Desktop: একই পেজে নিচে **EXTENSION PAIRING** → **Show pairing code**।
2. স্ক্রিনে কোড আসে: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (৮ গ্রুপ)।
3. extension popup → **Settings** → **Desktop pairing** → কোডটা পেস্ট →
   **Pair with desktop**।
4. প্রত্যাশিত: "Paired — the host verified the MAC on a test frame."
5. ভুল কোড দিলে: "That code looks wrong…" এবং কিছুই সেভ হয় না।
6. Desktop-এ **Revoke pairing** চাপলে কোড মুছে যায়; এরপর পুরনো কোড আর কাজ করে না।
7. **গুরুত্বপূর্ণ:** installed (release) build-এ পেয়ার না করা পর্যন্ত extension
   কিছুই পড়তে পারবে না — popup-এ "extension not paired — … Show pairing code"
   মেসেজ আসবে। এটা বাগ নয়, নিরাপত্তার নিয়ম।
8. পেয়ার করার পর host-এর প্রতিটা উত্তর (reply) sign হয়। কোনো reply-তে হাত
   দেওয়া হলে বা অন্য প্রোগ্রাম উত্তর দিলে popup দেখাবে "host reply failed the
   pairing check — re-pair the extension" — ভল্টের ডেটা দেখাবে না।
9. installed build host-টা তখনই চলে যদি তাকে সত্যিকারের browser চালু করে
   (Chrome/Edge/Firefox/Brave/Vivaldi/Opera), আর সেই browser-এর ফাইলটি তার
   নির্মাতার সই করা (Authenticode)। অন্য কোনো প্রোগ্রাম host চালু করলে popup-এ
   আসবে "native host refused: it was not started by a browser …"। এটাও বাগ নয়।
   LibreWolf/ungoogled Chromium-এর মতো unsigned browser ব্যবহার করলে host-এর
   environment-এ `PV_ALLOW_UNSIGNED_BROWSER=1` দিলে চলবে। এই সুইচ browser-এর সই
   যাচাই দুর্বল করে, তাই শুধু নিজে বানানো বা নিজের বিশ্বাস করা browser-এর জন্য
   ব্যবহার করুন।

### 8.C দৈনন্দিন ব্যবহার

| # | ধাপ | প্রত্যাশিত |
|---|---|---|
| A1 | একটা লগইন পেজ খুলুন (যেমন demo site) | পাসওয়ার্ড ফিল্ডে ক্লিক করলে dropdown আসে |
| A2 | dropdown থেকে আইটেম বাছুন | username + password ভরে যায় |
| A3 | username স্টেপ আলাদা (Google-স্টাইল) | আগে username, পরের ধাপে password |
| A4 | নতুন লগইন সাবমিট করুন | "Save login?" panel আসে (৬০ সেকেন্ড), folder/title বদলানো যায় |
| A5 | "Never suggest on this site" | ওই সাইটে আর সাজেশন আসে না |
| A6 | popup খুলুন (toolbar আইকন) | সব ধরনের আইটেম, সার্চ, folder ফিল্টার |
| A7 | একটা আইটেমে ক্লিক → View/Edit | masked secret, Edit/Fill/Close |
| A8 | popup-এ নতুন আইটেম যোগ/এডিট/ডিলিট | ডেস্কটপ ভল্টে সাথে সাথে দেখা যায় |
| A9 | 2FA কোড popup-এ | কোড + কাউন্টডাউন, **Fill 2FA code** কাজ করে |
| A10 | ডেস্কটপ অ্যাপ বন্ধ করে popup খুলুন | offline cache থেকে লিস্ট আসে (Hello/PIN চাইতে পারে) |
| A11 | Clipboard auto-clear | কপি করার ৩০ সেকেন্ড পরে ক্লিপবোর্ড খালি |
| A12 | Auto-lock | নির্দিষ্ট সময় নিষ্ক্রিয় থাকলে আবার পাসওয়ার্ড/Hello চায় |
| A13 | ডেস্কটপ **PIN** দিয়ে আনলক করুন, তারপর popup খুলুন | Settings → Security-তে *Browser bridge after PIN unlock* **চালু** থাকলে extension সাথে সাথে ভল্ট দেখায় |
| A14 | ওই toggle **বন্ধ** করে লক → PIN দিয়ে আনলক → popup খুলুন | popup একবার **অ্যাপ PIN** চায় ("Unlock the bridge"); সঠিক PIN-এ ভল্ট খোলে, ডিস্কে plain token তৈরি হয় না |

### 8.D যা ইচ্ছাকৃতভাবে নেই (ফেল লিখবেন না)

- ৬৪০px dual-column HUD — বাতিল করা হয়েছে।
- Organizations / collections — মডেলে নেই।
- iframe-এর ভিতরের ফিল্ড autofill হয় না (শুধু top frame)। একই কারণে cross-origin
  iframe-এর লগইনে "breach" সংকেতও আসে না; top-frame লগইনে আসে।
- "AES-256-GCM", "quantum-immune", "0 ms leak" — এসব দাবি ইচ্ছাকৃতভাবে **নেই**।

### 8.E সমস্যা হলে (Troubleshooting)

| উপসর্গ | কারণ | কী করবেন |
|---|---|---|
| ডেস্কটপ অ্যাপ খোলা ও আনলক করা, তবু popup বলছে "Vault is Locked" | ০.৪.২-এর আগের build, অথবা Settings → Security-তে *Browser bridge after PIN unlock* **বন্ধ** (strict mode)। তখন PIN আনলক কোনো bridge credential (`vault_hello.dpapi`) সিল করে না | হয় ডেস্কটপ লক করে **master password** দিয়ে একবার আনলক করুন, নয়তো ওই toggle **চালু** করুন। ডিফল্টে চালু — তখন PIN আনলকেই extension কাজ করে |
| Settings-এ *Browser bridge after PIN unlock* চালু আছে, তবু extension বলে credential নেই | অ্যাপটা PIN দিয়ে আনলক হয়েছে কিন্তু credential সিল হওয়ার আগেই popup খোলা হয়েছে, অথবা `vault_hello.dpapi` কেউ মুছে দিয়েছে | লক করে আবার আনলক করুন (PIN হলেও চলবে)। তারপরও না হলে master password দিয়ে একবার আনলক করুন |
| PIN আনলকে bridge বন্ধ রাখতে চাই, কিন্তু extension PIN চাইছে | এটাই strict mode-এর প্রত্যাশিত আচরণ। host-এর কাছে plain token থাকে না, তাই প্রতি ব্রাউজার সেশনে (host প্রসেস) একবার অ্যাপ PIN লাগে | কিছু করার নেই — এটাই সুরক্ষার বিনিময়। `SECURITY.md` → "PIN unlock and the browser bridge" |
| popup-এ PIN দিচ্ছি, বলছে "ভুল PIN — N বার বাকি" | অ্যাপ PIN-ই লাগে (ডেস্কটপ আনলকের PIN), extension PIN নয়। কাউন্টারটা ডেস্কটপের সাথে **শেয়ার করা** | ডেস্কটপের PIN-টাই দিন। ভুল করতে করতে ৫ বার হলে অ্যাপ PIN মুছে যাবে — তখন master password দিয়ে আনলক করে নতুন PIN সেট করুন |
| popup বলছে "Too many wrong PINs — the app PIN was wiped" | ৫-স্ট্রাইক নিয়ম: sealed master shred হয়ে গেছে | master password দিয়ে ডেস্কটপ আনলক করুন → Settings → Windows Hello/App PIN → নতুন PIN |
| popup-এ "native host refused: it was not started by a browser" | release host শুধু সই করা browser-এর spawn সার্ভ করে (A27 L1) | extension-টা Chrome/Edge/Firefox/Brave/Vivaldi/Opera থেকে খুলুন |
| popup-এ "not code-signed" | browser-এর Authenticode সই নেই (LibreWolf, ungoogled Chromium, নিজের বানানো build) | শুধু নিজের বিশ্বাস করা browser হলে host-এর environment-এ `PV_ALLOW_UNSIGNED_BROWSER=1` দিন। এতে সুরক্ষা দুর্বল হয় |
| popup-এ pairing সংক্রান্ত error | ডেস্কটপ আর extension একসাথে আপডেট হয়নি | Settings → Sync & Devices → Extension pairing → নতুন কোড নিয়ে popup-এ দিন |

---

## 9. Settings-এর প্রতিটা ট্যাব

| ট্যাব | যা দেখতে হবে |
|---|---|
| Security | Screen Blackout, favicons toggle, Travel mode, Windows Hello/App PIN, Master password rotation, offline cache, **Browser bridge after PIN unlock** (ডিফল্ট চালু) |
| Sync & Devices | GitHub Sync, Per-item sharing, Secure Send, Business members, P2P, Browser Bridge + Extension pairing |
| Privacy | blocked domains, breach-check সেটিংস |
| Recovery | recovery kit, shards |
| Backups | backup now / schedule / restore |
| Dev & API | version, local API status, access log, developer options |

প্রতিটা টগল বদলে অ্যাপ বন্ধ করে আবার খুলুন — মানটা মনে থাকা উচিত।

---

## 10. Automated gates (টেকনিক্যাল, কিন্তু কমান্ড কপি-পেস্ট করলেই হবে)

PowerShell-এ প্রজেক্ট ফোল্ডারে:

```powershell
$env:CARGO_TARGET_DIR='C:\pv-target'; $env:CARGO_INCREMENTAL='0'
cargo test -j 1
cargo clippy --all-targets -j 1 -- -D warnings
npm test
npm run test:tokens
```

প্রত্যাশিত: প্রতিটা কমান্ডের শেষে `0 failed` / কোনো warning নেই /
`UI tokens OK: …`. রিপোর্টে সংখ্যাগুলো লিখুন (যেমন "633 passed, 0 failed")।

> ধীর মেশিনে `cargo test` ১-২ মিনিট, প্রথম `clippy` ১০-২০ মিনিট লাগতে পারে।
> `Allocation failed` এলে Chrome বন্ধ করে আবার চালান — কোডের সমস্যা নয়।

---

## 11. যা এখনও অসম্পূর্ণ (জেনে রাখুন, ফেল নয়)

- **Binaries unsigned** → Windows SmartScreen সতর্কতা দেবে; in-app updater
  এই বিল্ড refuse করে।
- **Windows Hello** সব মেশিনে থাকে না; থাকলে টেস্ট করুন, না থাকলে স্কিপ।
- **Firefox bridge** আসল Firefox-এ যাচাই করা হয়নি — একবার চালিয়ে দেখুন।
- **কিছু সিস্টেম-মেসেজ ইংরেজিতে** থাকবে (localization আংশিক)।
- **Response MAC** আর **Authenticode publisher check** — দুটোই হয়ে গেছে (A27 L1/L2)। বাকি শুধু নথিভুক্ত সীমা: revocation চেক হয় না, আর `PV_ALLOW_UNSIGNED_BROWSER=1` hatch-টা যে প্রসেস spawn করে সে নিজেই সেট করতে পারে।
- **যেকোনো Chromium/Firefox ব্রাউজার** (Chrome, Edge, Brave, Helium, Thorium, Yandex, Firefox, LibreWolf, Waterfox, Zen, Floorp) এখন কাজ করে। কারণ Chromium হোস্টকে সরাসরি চালায় না — `cmd.exe /d /s /c "…" <pipe >pipe` দিয়ে চালায়। তাই host এখন immediate parent নয়, **ancestor chain** (৪ ধাপ পর্যন্ত) দেখে ব্রাউজার খোঁজে, আর signer টেবিলে fork-দের vendor token আছে (Helium = `imput LLC`)। লগে দেখবেন `spawn chain: …cmd.exe <- …chrome.exe`। নতুন কোনো fork আটকালে: `PV_TRUSTED_BROWSER_SIGNERS=vendorname` (env, audit-log হয়)।
- **পেয়ারিং কোড কপি:** Settings → Sync & Devices → **Show pairing code** → পাশের **📋 Copy code** বাটন। ক্লিপবোর্ড ১২০ সেকেন্ড পরে নিজে পরিষ্কার হয় (কোডটাই secret)। popup-এ "Vault is Locked" দেখালে এখন **🔗 Pair with desktop** বাটনও আসে — চাপলে Settings ট্যাব খুলে pairing ঘরে কার্সর বসে, কোড পেস্ট করে **Pair with desktop** চাপুন, তারপর **Retry**।
- **"ENCLAVE MODE" / "LOCAL ENCLAVE SYNCHRONIZED"** — পুরনো UI লেবেল,
  নিরাপত্তার দাবি নয়।

---

## 12. স্মোক টেস্ট (১৫ মিনিট, প্রতিবার release-এর আগে)

নতুন build ইনস্টল করার আগে/পরে (একবারই লাগে):

1. অ্যাপ পুরোপুরি বন্ধ করুন (tray-তেও থাকা যাবে না)।
2. `PhantomVault-Setup-0.4.2.exe` চালান। ভল্ট ফাইল (`my_secure_vault.enc`) কখনো মুছে যায় না — ইনস্টলার শুধু exe বদলায়। আপনার এক্সটেনশন ID (allowed_origins) আর pairing ফাইলও থাকে: ইনস্টলার আগে থেকে থাকা `%LOCALAPPDATA%\PhantomVault\native-host.json` আর `native-host-firefox.json` আর লেখে না।
3. `C:\Users\<you>\AppData\Local\Programs\PhantomVault\exe_integrity.dpapi` মুছে দিন। নতুন exe-র hash আলাদা, তাই এটা না মুছলে lock screen-এ "tampered" ব্যানার আসবে (ব্যানারটা ঠিকই কাজ করছে — সেটাই ট্রিপওয়্যার)।
4. অ্যাপ খুলে একবার master password (বা PIN) দিয়ে আনলক করুন।
5. Settings → Sync & Devices → **Show pairing code** → কোড কপি করুন।
6. এক্সটেনশন reload করুন (`chrome://extensions` → Reload), popup → Settings → **Desktop pairing** → কোড বসিয়ে **Pair with desktop**।

তারপর:

1. §3 প্রস্তুতি → unlock।
2. একটা login যোগ করুন → লক → unlock → আইটেমটা আছে।
3. Extension: popup খুলুন → আইটেম দেখা যায় → Fill কাজ করে।
4. §8.B পেয়ারিং: কোড দেখান → pair → "Paired…"।
5. Revoke → আবার pair।
6. Backup now → ফাইল তৈরি।
7. লক করে ভুল পাসওয়ার্ড → খোলে না।

সাতটার সবগুলো ঠিক = স্মোক পাস। একটা ফেল = release আটকান।

---

## 13. টেস্টারের ট্র্যাপ (এই মেশিনে যা যা হয়েছে)

- Chrome/UIA ক্লিকের সময় অন্য উইন্ডো ফোকাস চুরি করে — ক্লিক মিস হলে
  আগে অ্যাপে ক্লিক করে ফোকাস ফিরিয়ে নিন।
- লম্বা Settings পেজে বাটন নিচে থাকলে স্ক্রল করুন; নাহলে ক্লিক ভুল জায়গায় লাগে।
- `StartAllBack` নামের সফটওয়্যার থাকলে মাঝে মাঝে "Bad Image" বক্স আসে —
  বন্ধ করে আবার চেষ্টা করুন, এটা PhantomVault-এর বাগ নয়।
- পাসওয়ার্ড/কোড কখনো স্ক্রিনশট বা চ্যাটে দেবেন না।

---

## 14. ফলাফল লেখার ছক (কপি করে পূরণ করুন)

```
তারিখ:
Build version:
Windows version:
Chrome/Firefox version:
টেস্টার:

§4  প্রথম চালু/আনলক/লক      : PASS / FAIL (কোন ধাপ: ___)
§5  ভল্ট (A–I)               : PASS / FAIL (কোন ধাপ: ___)
§6  ব্যাকআপ/রিকভারি/ইমপোর্ট   : PASS / FAIL (কোন ধাপ: ___)
§7  সিঙ্ক (A–C)              : PASS / FAIL / SKIP (PAT নেই)
§8  এক্সটেনশন (A–D)          : PASS / FAIL (কোন ধাপ: ___)
§9  Settings ট্যাব            : PASS / FAIL (কোন ধাপ: ___)
§12 স্মোক (৭ ধাপ)             : PASS / FAIL

Automated gates:
  cargo test -j 1            : __ passed / __ failed
  cargo clippy … -D warnings : EXIT __
  npm test                   : __ passed / __ failed
  npm run test:tokens        : __

মন্তব্য:
```

ছকটা `docs/`-এ নতুন ফাইলে রাখবেন না — release note বা issue-তে পেস্ট করাই যথেষ্ট।
