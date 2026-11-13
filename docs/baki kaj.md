এখনো খোলা — সিকিউরিটি / প্রাইভেসি
#	গ্যাপ	ঝুঁকি
১	A-03 — container AEAD-এ header AAD নেই	আজ exploitযোগ্য নয় (সব হেডার ফিল্ড key derivation-এ যায়), কিন্তু ভবিষ্যতে ভঙ্গুর; format bump + migration লাগে
২	Binaries unsigned — Authenticode নেই, .sig নেই	SmartScreen warning; in-app updater এই বিল্ড refuse করবে
৩	Same-user process registered origin string জেনে native host spawn করতে পারে	pairing secret দরকার (ডিজাইন চেঞ্জ)
৪	Permission breadth — host_permissions:<all_urls>, tabs, scripting, clipboardWrite, nativeMessaging; hook.js সব http(s)-এ web-accessible	fingerprinting + SW compromise-এ blast radius
৫	PV_BREACH sender-scoped নয়	যেকোনো content script পাসওয়ার্ডের SHA-1 prefix পাঠাতে পারে (k-anonymity; পেজের কাছে পাসওয়ার্ড আগেই আছে) — কম ঝুঁকি
৬	Firefox bridge — valid_origin_format শুধু chrome-extension:// নেয় (native_host.rs:110)	আজকের Firefox প্যাকেজটা হয়তো host-এ connect করবেই না — আসল Firefox-এ যাচাই করা হয়নি
৭	.zwork লগ একবার git history-তে ঢুকেছে (2460772)	শুধু লোকাল পাথ, সিক্রেট নেই; force-push ছাড়া ইতিহাস থেকে মোছা যাবে না
এখনো খোলা — লজিক / UX
G3: export ব্যর্থতা নীরব — শুধু eprintln! (main.rs:12338, :12352, :12370)
G4: clipboard fallback ব্যর্থ হলেও "Copied" toast (main.rs:759)
G1: custom favicon সেট করার কোনো UI নেই (override_favicon emitter-হীন)
G2: checkbox custom field write-once
G6: sync conflict dead end (merge/pull-retry UI নেই)
G7: import undo লকে হারায়, বাটন থেকে যায়
G8: canary/PIN/access-log হেড রাইট নীরবে ব্যর্থ
G5 আংশিক: খোলা এডিটর এখন activity, কিন্তু সার্চ/ডিটেইলে টাইপ করলে টাইমার রিফ্রেশ হয় না
টেস্ট / টুলিং
তিনটা ফ্লেক (share_serve, loopback os 10053, crypto legacy) — -j 1-এ পাস, defuse করা হয়নি, শুধু ডক করা
Live E2E, DPI pass, স্ক্রিনশট — হয়নি
আমার সুপারিশ (পরের ৩টা)
Firefox origin + আসল Firefox-এ bridge টেস্ট — আজকের প্যাকেজের জন্য সবচেয়ে জরুরি, কারণ এটা ফাংশনাল ব্রেক হতে পারে।
G3 + G4 — নীরব ব্যর্থতা দুটো, ছোট ও ইউজার-দৃশ্যমান।
Signing key সেটআপ (বা A-03 format bump, যদি বড় কাজ করতে চাও)।
বলো কোনটা ধরব — ১ নম্বরটা আমি সবচেয়ে আগে করব, কারণ Firefox ইউজার এখন কিছুই পাবে না যদি origin check না মেলে।