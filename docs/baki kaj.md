এখনো খোলা — সিকিউরিটি / প্রাইভেসি
#	গ্যাপ	ঝুঁকি
২	Binaries unsigned — Authenticode নেই, .sig নেই	SmartScreen warning; in-app updater এই বিল্ড refuse করবে
৩	Same-user process registered origin string জেনে native host spawn করতে পারে	pairing secret দরকার (ডিজাইন চেঞ্জ)
৪	Permission breadth — host_permissions:<all_urls>, tabs, scripting, clipboardWrite, nativeMessaging; hook.js সব http(s)-এ web-accessible	fingerprinting + SW compromise-এ blast radius
৫	PV_BREACH sender-scoped নয়	যেকোনো content script পাসওয়ার্ডের SHA-1 prefix পাঠাতে পারে (k-anonymity; পেজের কাছে পাসওয়ার্ড আগেই আছে) — কম ঝুঁকি
৬	Firefox bridge — আসল Firefox-এ যাচাই করা হয়নি (কোড ঠিক, manifest writer টেস্টেড)	কোড পাথে সমস্যা থাকলে Firefox ইউজার কিছুই পাবে না
৭	.zwork লগ একবার git history-তে ঢুকেছে (2460772)	শুধু লোকাল পাথ, সিক্রেট নেই; force-push ছাড়া ইতিহাস থেকে মোছা যাবে না — wontfix

এখনো খোলা — লজিক / UX
G1: custom favicon সেট করার কোনো UI নেই (override_favicon emitter-হীন)
G2: checkbox custom field write-once (editor-এ toggle করা যায় না, appwindow.slint:3091)
G5: সার্চ/ডিটেইলে টাইপ করলে last_activity রিফ্রেশ হয় না — auto-lock টাইপিংয়ের মাঝখানে ফায়ার করতে পারে, draft হারায়
G6: sync conflict dead end (merge/pull-retry UI নেই)
G8 (আংশিক): access-log write failure এখন counter + stderr-এ যায়, কিন্তু UI-তে দেখানো হয় না

বন্ধ হয়েছে
A-03: container header এখন AEAD AAD-bound — `PV4\0` + mode byte; v2/v3 পড়া যায়, নতুন save সব v4. দাম: পুরোনো build v4 vault খুলবে না, সব ডিভাইস একসাথে আপডেট করতে হবে.
G3: export ব্যর্থতা এখন UI-তে দেখায়
G4: clipboard fallback `set_text` যাচাই করে, ব্যর্থ copy আর "Copied" দেখায় না
G7: lock-এ "Undo last import" বাটনও যায় (store-এর সাথে)
G8: access-log append ব্যর্থতা গোনা হয়, প্রথম ও প্রতি ১০০তম stderr-এ

টেস্ট / টুলিং
তিনটা ফ্লেক (share_serve, loopback os 10053, crypto legacy) — -j 1-এ পাস, defuse করা হয়নি, শুধু ডক করা
Live E2E, DPI pass, স্ক্রিনশট — হয়নি

আমার সুপারিশ (পরের ৩টা)
G5 — auto-lock টাইপিংয়ের মাঝখানে ফায়ার করলে unsaved draft হারায়; logic-only, test দিয়ে cover করা যায়।
G2 — checkbox custom field write-once, ইউজার আটকে যায়; ছোট UI fix।
G6 — sync conflict dead end; sync আটকে গেলে ইউজার কিছু করতে পারে না।
Signing key সেটআপ (Authenticode) — আপনার সিদ্ধান্ত, সার্টিফিকেট লাগবে।
