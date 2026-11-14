এখনো খোলা — সিকিউরিটি / প্রাইভেসি
#	গ্যাপ	ঝুঁকি
২	Binaries unsigned — Authenticode নেই, .sig নেই	SmartScreen warning; in-app updater এই বিল্ড refuse করবে
৩	Same-user process registered origin string জেনে native host spawn করতে পারে	pairing secret দরকার (ডিজাইন চেঞ্জ, আলাদা ২–৩ দিনের ব্যাচ)
৪	Permission breadth — host_permissions:<all_urls>, tabs, scripting, clipboardWrite, nativeMessaging; hook.js সব http(s)-এ web-accessible	fingerprinting + SW compromise-এ blast radius. সিদ্ধান্ত: wontfix + নথিভুক্ত — <all_urls> ছাড়া autofill হয় না
৫	PV_BREACH sender-scoped নয় — যেকোনো content script পাসওয়ার্ডের SHA-1 prefix পাঠাতে পারে	k-anonymity, পেজের কাছে পাসওয়ার্ড আগেই আছে — কম ঝুঁকি. `reuse` leak বন্ধ হয়েছে (নিচে)
৬	Firefox bridge — আসল Firefox-এ যাচাই করা হয়নি (কোড ঠিক, manifest writer টেস্টেড)	কোড পাথে সমস্যা থাকলে Firefox ইউজার কিছুই পাবে না
৭	.zwork লগ একবার git history-তে ঢুকেছে (2460772)	শুধু লোকাল পাথ, সিক্রেট নেই; force-push ছাড়া ইতিহাস থেকে মোছা যাবে না — wontfix

এখনো খোলা — লজিক / UX
U1	Modal-গুলোর ভিতরের `Rectangle`-এ `height` নেই → parent (পুরো window) height নেয়, dialog লম্বা হয়ে ফাঁকা জায়গা দেখায়। ঠিক হয়েছে শুধু "+ Add Custom Field"-এ (`height: cfdlg_lay.preferred-height`); বাকিগুলো একটার পর একটা স্ক্রিনে দেখে ঠিক করতে হবে — `x: (parent.width - self.width) / 2` প্যাটার্নে লাইন 2080, 3511, 3572, 3607, 3640, 3666, 3785, 3820, 3855 (কোনোটায় ScrollView থাকলে preferred-height 100% হয়, ওখানে min/max দিয়ে pin করতে হবে)

বন্ধ হয়েছে
A-03: container header এখন AEAD AAD-bound — `PV4\0` + mode byte; v2/v3 পড়া যায়, নতুন save সব v4. দাম: পুরোনো build v4 vault খুলবে না, সব ডিভাইস একসাথে আপডেট করতে হবে.
G1: detail pane-এ 🖼️ বাটন → `override_favicon` (custom logo সেট/বদল)
G2: checkbox custom field এখন editor-এ toggle হয় (`true`/`false`); স্ক্রিনে যাচাই — খালি box → সবুজ + tick (2026-11-14)
G2-fix: আগের `TouchArea`-এর ভিতরের glyph রেন্ডার হচ্ছিল না; এখন box+`Path` দিয়ে আঁকা, font-নির্ভর নয়
Add Custom Field dialog: content-sized (`cfdlg_lay.preferred-height`) — আগে পুরো window জুড়ে লম্বা ছিল
G3: export ব্যর্থতা এখন UI-তে দেখায়
G4: clipboard fallback `set_text` যাচাই করে, ব্যর্থ copy আর "Copied" দেখায় না
G5: সার্চ/2FA Hub-এ টাইপ করলে idle clock রিফ্রেশ হয় (`touch_activity`)
G6: sync fork আর dead end নয় — union merge stage হয় fork warning সহ, Apply শুধু locally merge করে (push বন্ধ), audit log-এ `merge forced`
G7: lock-এ "Undo last import" বাটনও যায় (store-এর সাথে)
G8: access-log append ব্যর্থতা গোনা হয়, প্রথম ও প্রতি ১০০তম stderr-এ, এবং audit viewer-এ "N write(s) failed this session" দেখায়
PV_BREACH: `reuse` count আর content-script sender-এর কাছে যায় না (vault-membership oracle বন্ধ); popup-এ থাকে; empty password host spawn করে না

টেস্ট / টুলিং
তিনটা ফ্লেক (share_serve, loopback os 10053, crypto legacy) — -j 1-এ পাস, defuse করা হয়নি, শুধু ডক করা
`Instant - Duration` Windows-এ panic করে (QPC origin) — টেস্টে `checked_sub` ব্যবহার করতে হবে
GitHub Dependabot ১টা moderate alert দেখায়: `RUSTSEC-2023-0071` (`rsa` Marvin) — `ssh-key`-এর optional dep, build graph-এ নেই; `audit.toml` + CI-তে ignore করা
Live E2E, DPI pass, স্ক্রিনশট — installer ইনস্টল + extension reload ছাড়া হয় না
UI harness trap: `setedit` (UIA ValuePattern) টেক্সট দেখায় কিন্তু Slint binding-এ সবসময় পৌঁছায় না — Save চাপলে "needs a title + key fields" আসতে পারে; এন্ড-টু-এন্ড save যাচাই করতে আসল keystroke দরকার
UI harness trap: `click -Arg Save` ভুল টেক্সট ধরতে পারে ("0 saved") — বাটনের rect `dump` থেকে নিয়ে `clickshot` ব্যবহার করা নিরাপদ

আমার সুপারিশ (পরের ৩টা)
Native-host pairing secret — same-user process host spawn আটকাতে একমাত্র আসল fix; ডিজাইন চেঞ্জ, ২–৩ দিন।
Signing key সেটআপ (Authenticode) — আপনার সিদ্ধান্ত, সার্টিফিকেট লাগবে।
Firefox live bridge check — আপনার মেশিনে Firefox unpacked extension লোড করে একবার যাচাই।
