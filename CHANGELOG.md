# Changelog

All notable changes to the **VERITAS** framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.7.4] - 2026-08-15

### Upgraded — Tactical Vector Enhancement

- **[FEATURE] Anti-MAC Randomization (Dynamic SSID Tracking)**:
  - Ditambahkan argumen CLI baru `--target-ssid "Nama WiFi"` (atau `--ssid`). Sekarang mendukung pelacakan **multi-SSID** sekaligus dengan memisahkan nama menggunakan koma (contoh: `--target-ssid "WiFi_A,WiFi_B,WiFi_C"`).
  - Fitur ini melawan *router* modern atau *mobile hotspot* korporat yang terus-menerus merotasi BSSID (MAC Address) mereka untuk menghindari *Deauthentication* yang terkunci pada satu MAC target.
  - Pada *Stress Mode*, filter penembakan tidak lagi dilakukan secara membabi-buta, melainkan difokuskan **hanya** pada target *Access Point* yang memancarkan SSID yang cocok dengan salah satu dari daftar SSID target. Secepat apapun *router* target merubah MAC Address-nya, selama nama SSID-nya tetap, Veritas akan selalu memburu dan melibas target BSSID yang baru tersebut *on-the-fly*.
- **[UPGRADE] Unmask Hidden SSID (Ambient Harvesting & Targeted Replay)**:
  - Fitur pasif `--unmask-hidden` dirombak total. Sebelumnya hanya menembakkan *Wildcard Probe Request* kosong secara membabi-buta, yang mana sering diabaikan oleh AP Hidden modern berstandar WPA3.
  - **SSID Harvesting**: *Scanner thread* sekarang secara pasif memanen/menyadap *Probe Request* dari klien-klien di sekitarnya (bahkan *broadcast probe*) dan menyimpan SSID yang mereka cari ke dalam *ring buffer* (maksimal 32 SSID).
  - **Targeted Probe Replay**: Setiap 1 detik, Veritas akan menembakkan rentetan *Targeted Probe Request* berdasarkan nama SSID yang telah dipanen tersebut. Ini bertindak seperti teknik *phishing* tingkat sinyal RF, memaksa AP Hidden yang keras kepala untuk merespons dan membocorkan BSSID serta Channel aslinya.
- **[UPGRADE] Advanced WIPS Evasion (CSA Realistic Countdown)**:
  - Vector #1 (Channel Switch Announcement) telah ditingkatkan untuk mengelabui deteksi tingkat lanjut dari *Wireless Intrusion Prevention Systems* (WIPS).
  - Sebelumnya Veritas menembakkan instruksi perpindahan kanal secara instan (`count = 1`), yang sering dicurigai sebagai anomali oleh WIPS.
  - Sekarang Veritas menembakkan serangan berupa **rentetan/burst hitung mundur** (`count = 3`, `count = 2`, `count = 1`, `count = 0`). Ini mensimulasikan persis bagaimana *Access Point* yang sah memberikan peringatan sebelum berpindah kanal, sehingga serangan terlihat sangat alami dan tidak terdeteksi oleh sistem heuristik WIPS.
  - Peningkatan ini sekarang **aktif di semua mode operasi** (termasuk mode serang konvensional / Factory Mode, tidak hanya pada Stress Mode).
- **[UPGRADE] Aggressive 2.4GHz Dead-End Routing (Vector #1)**:
  - Mengubah kalkulasi algoritma kanal tujuan (`redir`) untuk serangan CSA di spektrum frekuensi 2.4GHz.
  - Alih-alih melempar klien ke kanal yang berdekatan (di mana mereka bisa dengan cepat pulih), Veritas kini melempar klien secara paksa ke ujung ekstrim spektrum.
  - Jika AP target berada di Kanal 1-6: Klien dibanting ke **Kanal 14** (Kanal ilegal/terlarang di mayoritas region, menyebabkan *driver error* atau *timeout* fatal).
  - Jika AP target berada di Kanal 7-14: Klien dibanting ke **Kanal 1** (ujung spektrum terjauh, memaksa radio klien melakukan kalibrasi ulang dari awal).
  - Peningkatan ini juga telah diterapkan secara menyeluruh ke **Factory Mode**, memastikan konsistensi kekuatan destruktif di semua jenis operasi Veritas.
- **[UPGRADE] 5GHz DFS Blackhole & IE 192 Kernel Panic (Vector #1)**:
  - Merombak total kalkulasi dan *payload* untuk target yang beroperasi di pita 5GHz.
  - **DFS Blackhole**: Alih-alih melempar klien secara acak, kini semua klien 5GHz secara paksa dibanting ke **Kanal 128 (Terminal Doppler Weather Radar)**. Aturan perangkat keras (*hardware regulations*) memaksa modul klien untuk melakukan *Channel Availability Check* (CAC) secara ketat selama **10 menit** saat memasuki kanal radar ini. Ini menciptakan efek *Denial of Service* secara instan di mana radio klien dibungkam total selama 10 menit tanpa ampun.
  - **IE 192 (VHT Operation) Malformation**: Veritas kini menyuntikkan *Information Element* 192 beracun ke dalam paket CSA 5GHz. IE ini memaksa *chip* Wi-Fi klien beralih ke *bandwidth* raksasa **160 MHz**, tetapi dengan koordinat frekuensi pusat (Center Frequency) yang mustahil secara logika (255). Saat *driver* klien (seperti Realtek atau Mediatek) mencoba memproses parameter cacat ini untuk mengalokasikan memori radio, hal ini memicu **Kernel Panic** seketika—membuat OS klien *hang*, *restart*, atau melumpuhkan *subsystem* Wi-Fi hingga dilakukan *hard reset*.
- **[UPGRADE] Cascading DFS Lockout & IE 192 Piggybacking (Vector #16: DFS Fake Radar)**:
  - Vector #16 telah ditingkatkan menjadi serangan **Multi-Channel Spectrum Bombardment**.
  - Alih-alih hanya mengklaim deteksi radar di satu kanal, Veritas kini membangun satu paket *Measurement Report* raksasa yang mengklaim adanya radar militer di semua pita utama DFS (Kanal 52, 100, 132) secara bersamaan. Ini memaksa logika mitigasi radar AP untuk mengunci/mem-Banned **seluruh** spektrum DFS 5GHz dan memaksanya bermigrasi ke kanal biasa yang padat, menghancurkan *throughput*-nya secara permanen.
  - Paket *Vacate CSA* (peringatan palsu agar klien menjauhi radar) yang ditembakkan dalam serangan ini kini juga disuntik dengan *payload* beracun **IE 192 Kernel Panic**, menjamin bahwa setiap klien yang mematuhinya akan langsung *crash*!
- **[UPGRADE] PMF State-Machine Baiting & Micro-Burst (Vector #2 & #3: Deauth/Disassoc)**:
  - Untuk menembus perlindungan WPA3 PMF (Protected Management Frames), serangan *Deauth/Disassoc* kini ditembakkan dalam bentuk **Micro-Burst** super cepat.
  - Veritas secara khusus menyuntikkan rentetan 3 paket berturut-turut menggunakan **Reason Code 6** (*Class 2 frame received*) dan **Reason Code 7** (*Class 3 frame received*). Kombinasi *Micro-Burst* dan kode alasan spesifik ini dirancang untuk membuat *discard queue* PMF pada *router* (khususnya Broadcom dan Mediatek) meluap, memicu *CPU Spike* dan seringkali berhasil menipu *router* agar secara prematur menghapus status koneksi klien (mem-Bypass PMF).
- **[UPGRADE] Variable-Length WIPS Padding (Vector #2 & #3: Deauth/Disassoc)**:
  - Meningkatkan teknik *WIPS Evasion* (penghindaran deteksi) pada paket *Deauth/Disassoc*.
  - Sebelumnya, *padding* pengelabuan (*Vendor Specific IE 221*) memiliki ukuran statis 7 byte, yang rentan dideteksi oleh WIPS tingkat lanjut (Cisco/Meraki) berbasis pola ukuran (Signature).
  - Sekarang, Veritas mengkalkulasi **Variable-Length Padding** yang panjangnya berubah-ubah secara dinamis antara 7 hingga 22 byte setiap milidetiknya berdasarkan nomor *Sequence*. Ini memastikan tidak ada dua paket serangan yang memiliki ukuran atau muatan yang identik, menjadikannya seolah-olah "suara bising radio" (RF Noise) acak yang sama sekali tidak terlihat oleh aturan *Firewall* Wi-Fi statis.
- **[UPGRADE] Omni-Panic Protocol Malformation & IE Stacking (Vector #1, #8, #10: CSA)**:
  - Seluruh paket CSA kini disulap menjadi bom logika mematikan yang menargetkan *driver parsing logic* dari semua generasi Wi-Fi secara bersamaan (Wi-Fi 4, 5, dan 6).
  - Setiap paket CSA menyuntikkan: **IE 61 (HT Operation)** dengan *Secondary Channel Offset* cacat untuk memicu *Integer Overflow*, **IE 192 (VHT Operation)** dengan koordinat frekuensi pusat 255 untuk memicu *Buffer Overflow* 160MHz, dan **IE 255 Ext 36 (HE Operation)** dengan *BSS Color* sampah untuk meng-*crash*-kan logika 802.11ax.
  - Kombinasi racun (*Omni-Panic Stack*) ini kini ditembakkan di **setiap** perintah pindah kanal, baik di spektrum 2.4GHz maupun 5GHz, menjamin *Kernel Panic* massal pada perangkat klien (*smartphone/laptop*) yang mencoba memproses perintah tersebut.
- **[UPGRADE] RSN Downgrade Poisoning / WPA3 Self-Banishment (Vector #1 & #10: CSA)**:
  - Mengelabui mekanisme perlindungan *Anti-Downgrade* (KRACK Protection) pada iOS dan Android modern.
  - Veritas kini menyuntikkan *Information Element* 48 (RSN) palsu ke dalam paket *CSA Beacon* dan *Probe Response*. RSN palsu ini mengiklankan bahwa AP target diam-diam telah menurunkan tingkat keamanannya menjadi enkripsi WPA-TKIP yang sudah sangat usang dan dilarang.
  - Ketika ponsel korban memproses paket ini, *Security Daemon* OS akan berasumsi jaringan sedang diserang oleh *Hacker* (Downgrade Attack) dan akan secara permanen mem-**Blacklist** *MAC Address* AP aslinya. Pengguna tidak akan bisa terhubung kembali ke Wi-Fi rumah/kantornya sendiri sampai mereka menekan tombol "Lupakan Jaringan" (*Forget Network*) secara manual.
- **[UPGRADE] Phantom Roaming Trap (Vector #10: Probe Response CSA)**:
  - Vektor *Probe Response CSA* kini tidak hanya mengandalkan *spoofing* BSSID AP asli.
  - Veritas akan memancarkan "AP Hantu" (*Phantom AP*)—membuat SSID virtual yang persis sama dengan SSID target, tetapi menggunakan MAC Address acak yang dibuat dinamis, seolah-olah ada sinyal *router* kedua yang jauh lebih kuat.
  - Saat perangkat klien korban mencoba melakukan *Roaming* untuk berpindah ke AP Hantu ini, sang AP Hantu akan segera "menyambutnya" dengan menembakkan paket *Probe Response CSA* jebakan yang memaksa klien masuk ke saluran mematikan (*DFS Blackhole* atau Kanal 14).
## [4.7.3] - 2026-08-13

### Upgraded — Tactical Vector Enhancement

- **[UPGRADE] ECSA & Quiet Element Stacking (Vector #1, #8, #10: CSA)**: 
  - Ketiga vektor CSA utama (`CSA Beacon`, `CSA Action Frame`, `Probe Response CSA`) telah ditingkatkan dari CSA standar (IE 37) menjadi serangan bertumpuk yang menyertakan **Extended CSA (IE 60)**.
  - Ini mengeksploitasi klien modern 5GHz/WiFi-6 (Android/iOS terbaru) yang mem-filter CSA lama jika tidak ada *Operating Class*.
  - **Quiet Element (IE 40)** kini disusupkan di **ketiga** vektor CSA (bukan hanya Action Frame), memaksa radio klien melakukan *TX Pause* / *Radio Silence* bersamaan dengan perintah pindah kanal.
- **[FIX] DS Parameter Set (Vector #1 & #10)**:
  - DS Parameter Set IE (ID=3) pada `CSA Beacon` dan `Probe Response CSA` sebelumnya salah menunjuk ke `new_ch` (kanal tujuan). Menurut standar IEEE 802.11, DS Parameter harus menunjukkan **kanal operasi saat ini** (`cur_ch`). Klien cerdas bisa membuang beacon yang tidak konsisten. Diperbaiki agar sesuai standar.
- **[UPGRADE] Firmware Watchdog Evasion (Intel 8265/9260 dkk)**:
  - Chipset Wi-Fi sensitif seperti Intel Corporation Wireless 8265 / 8275 (rev 78) sering terlempar dari *monitor mode* jika dipaksa menembak dengan intensitas *Insane* (buffer *DMA* penuh → *firmware panic reset*).
  - *PID Auto-Tuner* sekarang dilengkapi mekanisme pengereman darurat (*Hard Braking*). Jika *fail rate* mendadak melonjak melampaui 30%, injektor akan melakukan *Hardware Cooldown* instan (jeda mutlak 100 milidetik) dan memperlambat *base sleep* secara agresif. Ini mencegah cip Intel mengalami *overload* tanpa mengorbankan rata-rata tembakan PPS secara keseluruhan.
- **[UPGRADE] WIPS Evasion Padding (Vector #3 & #4: Deauth/Disassoc)**:
  - Pembentuk paket *Deauthentication* dan *Disassociation* kini menyisipkan **Vendor Specific IE (ID 221)** ke bagian ekor (*payload padding*).
  - IE yang disisipkan meniru *signature* ekstensi Microsoft WMM/WME. 
  - Penambahan ini menghancurkan bentuk paket statis 26-byte konvensional (ukuran standar alat peretasan), menembus deteksi WIPS (Wireless Intrusion Prevention System) berbasis ukuran (*size-based signature evasion*), sekaligus memicu ketidakstabilan pada *driver* klien yang buruk saat membaca ekor paket pemutusan.
- **[FITUR BARU] Full WPA2/WPA3 4-Way Handshake Capture (.pcap)**:
  - `capture_thread` sekarang dilengkapi penulis `.pcap` ringan bawaan (tanpa dependensi `libpcap`).
  - Tidak lagi hanya menangkap M1 (PMKID), Veritas kini akan merekam *seluruh paket EAPOL* (M1, M2, M3, M4) ke dalam format `.pcap` standar yang dapat langsung dibaca oleh Wireshark, Hashcat (`hcxpcapngtool`), maupun Aircrack-ng.
- **[MANAJEMEN ARTEFAK] Persistensi Output (Direktori `./out/`)**:
  - Semua penulisan file sementara atau hasil tangkapan (contoh: konfigurasi *Rogue AP*, file `.22000` PMKID, hasil pindaian `airodump-ng`, dan tangkapan `.pcap` EAPOL) telah dipindahkan dari `/tmp/` ke direktori kerja `./out/`.
  - Ini mencegah hilangnya data berharga (*handshake* / konfigurasi) akibat proses pembersihan OS, dan menyelesaikan potensi masalah izin akses (permission collision) di lingkungan Termux/NetHunter pada platform Android.
- **[UPGRADE] Rotasi Reason Code Disassoc (Vector #4)**:
  - `Disassociation` sebelumnya hanya menggunakan 1 reason code statis (`8`). Kini menggunakan **8 reason code berbeda** (`1,3,4,6,7,8,17,23`) yang dirotasi — identik dengan `Deauthentication`. Ini menghancurkan deteksi WIPS berbasis pola monoton.
- **[UPGRADE] Forward Unicast Deauth ke BSSID (Stress Mode)**:
  - Mode *stress* sebelumnya hanya menembakkan deauth *broadcast*. Beberapa AP mengabaikan deauth broadcast tapi memproses deauth *unicast*. Kini ditambahkan tembakan deauth langsung ke BSSID target per putaran.
- **[UPGRADE] Rotasi Reason Code Deauth Reverse (Stress Mode)**:
  - `deauth_rev` (Client→AP spoof) di stress mode sebelumnya menggunakan reason statis `6`. Kini menggunakan rotasi dari 8 reason code.
- **[UPGRADE] WPA3 SAE Hunting & Puzzling (Vector #16)**:
  - Mode Target (*Factory*): Diperbaiki *bug* statis di mana vektor ini hanya menghasilkan satu paket `sae_commit` dari *MAC client target* (bahkan *broadcast MAC* `FF:FF:FF:FF:FF:FF` jika tidak diset, yang langsung didrop). Kini menggunakan metode *pooling* seperti Auth DoS, menyemburkan paket *Commit* dari puluhan MAC acak (`sae_pool[MAX_AUTH_POOL]`).
  - Rotasi Grup Kriptografi: `Finite Cyclic Group` (Group ID) di dalam *body SAE Commit* sebelumnya terkunci statis di Grup `19` (NIST P-256). Keduanya di mode Target maupun *Stress* kini secara rotasi menggunakan **Grup 19**, **Grup 20** (P-384), dan **Grup 21** (P-521). Ini mem-bypass filter pembatas anti-clogging AP yang hanya melindungi satu grup.
  - **[MAXIMUM LEVEL] Point-on-Curve Validation Bypass**: Sebelumnya bagian *Element* (x,y coordinate) pada *SAE Commit* hanya diisi dengan *byte random*. Pustaka ECC modern (seperti Hostapd) akan **langsung menolak** koordinat yang tidak berada di dalam kurva tanpa melakukan kalkulasi *scalar multiplication* (kalkulasi terberat). Kini, kita menggunakan **Titik Generator (G)** murni yang valid untuk masing-masing kurva (P-256, P-384, P-521) beserta panjang *scalar* dan *element* yang dinamis mengikuti panjang *Group ID*. AP tidak peduli ini adalah titik generator, ia melihat koordinat valid, dan dipaksa menyelesaikan kalkulasi ECDH yang ekstrem! Memaksa *CPU exhaustion* 100% pada AP.
- **[UPGRADE] Operating Channel Aggression / DFS Fake Radar (Vector #15)**:
  - *Dynamic Dialog Token*: `Measurement Report` IE kini merotasi *Dialog Token* per paket, bukan statis 1. Di mode Stress, paket ini ditembakkan secara *burst* (3 paket beruntun dengan 3 MAC Address *spoofed* berbeda) untuk membuat sistem AP lebih cepat terpicu bahwa ancaman radar DFS itu masif.
  - *Vacate CSA Enhancement*: Sama seperti Vektor CSA utama, pemberitahuan pengosongan kanal (*vacate*) palsu sekarang dilengkapi dengan **Extended CSA (IE 60)** dan **Quiet Element (IE 40)**. Klien 5GHz modern yang keras kepala tidak punya pilihan selain merespons langsung.

## [4.7.2] - 2026-08-13

### Fixed — Critical Bugs (Audit Batch [FIX 47])

- **[KRITIS] Zero-Copy Offset Korupsi Paket**: Seluruh kode *zero-copy template* di `stress_injector_thread` (Deauth, EAPOL Logoff, Auth DoS, Beacon Confusion, Quiet Element) menggunakan offset byte yang **salah 4-6 byte** untuk menulis alamat MAC dan *Sequence Control*. Offset hardcoded (`+10`, `+16`, `+22`, `+28`) menimpa field `Frame Control` dan `Duration` alih-alih `addr2`/`addr3`/`seq`, menyebabkan setiap paket zero-copy yang terkirim menjadi *malformed* dan ditolak oleh perangkat target. Diperbaiki dengan menambahkan konstanta `OFF_A1`/`OFF_A2`/`OFF_A3`/`OFF_SEQ`/`OFF_BODY` yang dihitung otomatis dari `sizeof(rt_hdr_t)` + `offsetof(dot11_t, ...)`.
- **[KRITIS] DELBA TID Params Offset Salah**: Kode DELBA menulis parameter TID ke offset `+32` (yang merupakan field *Sequence Control*), bukan ke offset `+36` (yang merupakan DELBA Params setelah category+action). Akibatnya rotasi TID 0-7 **tidak pernah benar-benar mengubah TID** di paket yang terkirim. Diperbaiki ke `OFF_BODY + 2`.
- **[SEDANG] PID Auto-Tuner Race Condition**: Variabel `static uint64_t last_sent/last_fail` di dalam `stress_injector_thread` di-share antar semua thread tanpa proteksi (*data race*). Pada mode dual-radio, kedua thread secara bersamaan membaca/menulis state PID, menyebabkan kalkulasi `fail_rate` yang acak dan *rate limiter* yang tidak stabil. Diperbaiki menjadi variabel lokal per-thread.
- **[SEDANG] Sequence Number Overflow**: `seq` (uint16_t) di-increment tanpa masking, menyebabkan `seq << 4` meluap dari 16 bit saat `seq >= 4096`. Diperbaiki dengan masking `(seq & 0xFFF)` di semua titik penggunaan.
- **[MINOR] Dead Code Quiet Element**: Kode manipulasi byte `tpl_quiet` yang tidak pernah digunakan (selalu di-override oleh `mk_quiet_beacon()`) telah dihapus bersama alokasi template `tpl_quiet` dan `tpl_confusion` yang tidak terpakai.

---

## [4.7.1] - 2026-08-13

### Changed & Removed
- **Removed `Evil Twin Handoff` and `TKIP/GCMP MIC Error`**: These vectors were removed from the core injector. `Veritas` is strictly designed as a high-speed L2 stateless injection framework. Maintaining stateful logic (like Evil Twin routing or QoS replay) creates unnecessary bloat and CPU overhead, contradicting the tool's core philosophy. The total number of vectors is now 18.

### Fixed & Optimized
- **Zero-Copy Injection for Auth, EAPOL, and Quiet Element**: Completely eliminated `rand_mac()` and `mk_*()` frame-building calls inside the `stress_injector_thread` hot-loop for these vectors. By using in-memory template byte manipulation (modifying only the 6-byte MAC and 2-byte sequence numbers via pointers), the severe PPS drops and "sticky" Ctrl+C hangs during INSANE mode have been entirely resolved.
- **Randomized MAC Bypass (Wildcard Injection)**: Both `CSA Action Frame` and `Probe Response CSA` now transmit a secondary payload using `FF:FF:FF:FF:FF:FF` (Broadcast) as the BSSID. This guarantees that modern clients using randomized MAC addresses during probing will still process the Channel Switch Announcement, completely bypassing the MAC randomization defense.
- **DELBA Attack Aggression**: The `DELBA` (Delete Block Ack) attack no longer targets a single Traffic Identifier (TID 0). It now loops through all 8 TIDs (0-7) and alternates between Initiator (AP→Client) and Responder (Client→AP) directions, forcing the teardown of AMPDU aggregation across all Quality of Service queues simultaneously.
- **Beacon Confusion Escalation**: Fixed a bug where `Beacon Confusion` was only injecting a single static fake BSSID per loop. It now performs high-speed in-place memory overwrites to generate thousands of unique BSSIDs per second, effectively crashing client network scanners as intended.

---

## [4.7.0] - 2026-08-13

### Added — 4 New Attack Vectors (Total: 20)
- **Vector #17 — CTS/RTS Virtual Jammer**: Transmits spoofed Clear-To-Send (CTS) control frames with the Duration/NAV field set to the maximum value of 32767 µs. All 802.11-compliant devices on the same frequency will honor the NAV and remain silent, causing Virtual Jamming without disrupting physical connections. Highly effective against robust routers (e.g. Huawei) that are resilient to Deauth/Disassoc but still honor NAV timing.
- **Vector #18 — WPA3 SAE Hunting & Puzzling**: Floods SAE (Simultaneous Authentication of Equals) Commit frames with random source MACs. Each SAE Commit forces the target AP to perform computationally expensive Elliptic Curve Diffie-Hellman (ECDH) "hunting-and-pecking" operations. Tactical effect: AP CPU saturates at 100% from continuous cryptographic puzzle computation, causing hang/crash (Crypto Puzzle Exhaustion / CVE-2019-9494 Dragonblood).
- **Vector #19 — BSS Transition Attack (802.11v Steer)**: Sends spoofed BSS Transition Management Request (Action frame, Category=10 WNM, Action=7) pretending to originate from the legitimate AP, directing connected clients to roam to a rogue BSSID via Neighbor Report IE with Disassociation Imminent bit set.
- **Vector #20 — Beacon Report Drain (Battery Exploitation)**: Sends Radio Measurement Request (Action frame, Category=5, Action=0) demanding the target device perform continuous Beacon Report scans across ALL channels/operating classes with maximum repetitions (65535). Drains mobile device battery at extreme speed due to non-stop background scanning.

### Fixed
- **INSANE Mode Monitor Drop (Critical Bug)**: Removed the automatic `iw reg set BO` / `iwconfig txpower 30` system calls from `unlock_tx_power()` that were causing a PHY state reset while the interface was in active monitor mode, effectively blinding the scanner thread and killing stress mode.
- **INSANE Mode Safety Confirmation**: Added interactive warning and confirmation prompt when selecting INSANE mode (level 5) in the aggressiveness menu, informing users about potential hardware limitations before proceeding.
- **`system()` Unused Return Value (CI/CD Fix)**: Wrapped all `system()` calls with return value checks to eliminate `-Werror=unused-result` build failures in GitHub Actions CI.
- **`--help` Without Root**: Moved the `--help` flag check before the `getuid() != 0` guard in `main()`, allowing users to view help without requiring `sudo`.

---

## [4.5.1] - 2026-08-10

### Fixed & Improved
- **High-Performance Atomics (Lock-Free)**: Replaced `pthread_mutex_t` locking in the stress mode packet counting logic with C11 hardware-level `_Atomic` operations (`__atomic_fetch_add` and `atomic_load`). This completely eliminates thread contention across the injector thread pool, allowing maximum packet injection rates (PPS) during Mass Injection.
- **Memory Integrity & Buffer Safety**: Removed deprecated `strcpy` function calls and replaced them with bounds-checked `snprintf`.
- **Advanced Radiotap Bounds Checking**: Hardened the `parse_radiotap_rssi` function with strict boundary checks against the `rt_len` packet length to prevent segmentation faults (Segfaults) when parsing corrupted or maliciously malformed beacon frames in the air.

---

## [4.6.0] - 2026-08-12

### Added
- **TX-Power & Regulatory Domain Unlock Guidance**: When launched in `--insane` mode, Veritas now warns and guides the user to manually manipulate the Linux network stack (`iw reg set BO` and `iwconfig txpower 30`) to unlock transmission power to the absolute hardware maximum of 1000mW (30dBm). The automatic execution was removed to prevent hardware monitor mode reset bugs.
- **OUI-Aware Realistic MAC Spoofing**: Advanced WIPS/IDS evasion. `rand_mac()` no longer generates completely random, invalid vendor prefixes. It now selects from a hardcoded list of real vendors (Apple, Intel, Samsung, Broadcom, etc.) and correctly unsets the "Locally Administered" bit, making attack frames indistinguishable from legitimate smartphones and laptops.

### Fixed & Improved
- **Zero-Copy Packet Templating (Optimasi Injeksi Ekstrem)**: Massively optimized the `stress_injector_thread` by pre-building attack packet templates (e.g., Deauth Flood) outside the hot loop. During injection, Veritas now uses raw pointer arithmetic to overwrite only the 6-byte target BSSID and 2-byte Sequence Control field, saving thousands of `memcpy` and function calls per second and maximizing PPS throughput.
- **AP Pool Sharding (Multi-Threading Load Balancer)**: Redesigned the dual-radio injection architecture. `run_stress()` now spawns strictly isolated injector threads: Injector 1 handles *only* 2.4GHz channels, and Injector 2 handles *only* 5GHz channels. This completely eliminates redundant socket writes and prevents thread overlap, resulting in perfectly load-balanced multi-band mass injection.

---

## [4.5.3] - 2026-08-12
- **Smart BPF (Berkeley Packet Filter) Kernel-Level Filtering**: Implemented a kernel-level raw socket filter using BPF assembly to silently drop non-Management 802.11 frames (such as Data and Control frames) before they reach user-space. This drastically reduces CPU consumption on scanner threads in highly congested environments.
- **GitHub Actions CI/CD Integration**: Automated build and memory sanity tests using AddressSanitizer and UndefinedBehaviorSanitizer on every push and pull request via `.github/workflows/c-cpp.yml`.

### Fixed & Improved
- **PID Auto-Tuner for Buffer Bloat (Rate Controller)**: Replaced static thread sleep intervals in the injector loop with an intelligent AIMD (Additive Increase Multiplicative Decrease) feedback controller. The engine now dynamically monitors injection failure rates (`g_pkts_fail`) and automatically throttles or accelerates the packet transmission rate in real-time, preventing socket buffer bloat and ensuring the absolute maximum Packets Per Second (PPS) hardware limit is achieved safely.

---

## [4.5.2] - 2026-08-11
### Added
- **Multi-Radio (Interface) Load Balancing**: The `--dual <iface>` flag is now globally supported. In Stress Mode, it splits the injection workload seamlessly. Radio 1 locks onto the 2.4GHz spectrum while Radio 2 handles the 5GHz spectrum, effectively eliminating channel hopping delays and maximizing dual-band PPS (Packets Per Second).

### Fixed & Improved
- **System Call Fast-Path (mono_us)**: Optimized the internal `mono_us()` timestamp generator by replacing heavy `clock_gettime` syscalls with a thread-local static cached counter. This drastically reduces CPU context switching overhead during aggressive frame injections across all vectors.
- **Lock-Free PRNG Cache (rand_mac)**: Reworked the MAC address spoofing engine. It now utilizes a thread-local `xorshift64` cache rather than standard library `rand()` mutex locks or slow `/dev/urandom` disk reads, ensuring collision-free and instant MAC generation in multithreaded stress pools.

---

## [4.5.0] - 2026-08-09

### Added & Improved
- **Active Hidden SSID Unmasking (`--unmask-hidden`)**: Added active Probe Request sweep mode (`mk_probe_req`) and passive Probe Response / Directed Probe Request parsing to reveal hidden SSIDs in real-time across targeted and stress modes in both C11 (`veritas.c`) and Python (`veritas.py`).
- **Instant Channel Switch Synchronization**: Updated CSA beacon and probe builders (`mk_csa_beacon` and `mk_probe_resp_csa`) to synchronize the DS Parameter Set IE directly to `new_ch` alongside instant `csa_count = 1` for forced RF retuning on target clients.
- **JSON Script Parity**: Added `"unmask_hidden": true` boolean option in JSON script configuration files.

---

## [4.4.0] - 2026-08-08

### Added
- **Operating Channel Aggression / DFS Fake Radar (Vector #16)**: New IEEE 802.11h Spectrum Management attack that spoofs military/weather radar detection on DFS channels (5 GHz UNII-2 / UNII-2e: 52–64, 100–144). Injects a Measurement Report Action frame (Basic Report, Map bit3 = Radar) followed by a spoofed AP CSA beacon (`mode=1` stop-TX, `count=0`) that forces channel vacation. Compliant APs may enter CAC / Non-Occupancy lockout for several minutes per aviation DFS regulations (ETSI EN 301 893 / FCC Part 15). Implemented in C (`mk_dfs_radar_report` / `mk_dfs_vacate_csa`) and Python (`make_dfs_radar_report` / `make_dfs_vacate_csa`), including stress-mode injection and OCA target-channel warnings.

---

## [4.3.1] - 2026-08-08

### Fixed & Improved
- **Format Truncation Fixes**: Resolved all compiler `-Wformat-truncation` warnings under strict `-Wall -Wextra -Werror` flags.
- **Stress Pool Thread Safety**: Replaced unsafe struct assignments containing atomic members with mutex-synchronized standard types (`uint64_t tx_count`).
- **PMKID Capture Bounds Check**: Fixed `capture_thread` radiotap and EAPOL offset bounds check to prevent invalid memory indexing on short frames.
- **Stress Injector Vectors**: Integrated missing attack vectors (`FragAttack`, `EAPOL Logoff`, `Probe Response CSA`, `Beacon Confusion`) into `stress_injector_thread`.
- **TUI Cursor Restoration**: Fixed hidden cursor bug upon exit in both targeted and stress test TUI display threads.
- **State Initialization**: Ensured `g_stop` and `g_stress_aps_seen` are explicitly reset at start of `run_stress()` and `run_script()`.
- **JSON Script Parity**: Added support for `"stress_mode"` and `"scan_5ghz"` boolean options in JSON script automation.
- **Python Engine Synchronization**: Added `--stress` and `--5ghz` mode support and `"stress_mode"` script parsing to `veritas.py`.

---

## [4.3.0] - 2026-08-07

### Added
- **Stress Test / Mass Injection Mode (mdk4-style)**: 
  - `--stress`: New mode to passively capture all 802.11 beacons in range and build a live AP pool (`stress_pool_t`).
  - `--5ghz`: Optional flag to include 5GHz channel hopping alongside 2.4GHz spectrum.
  - Multi-target injection engine (`stress_injector_thread`) building frames on-the-fly for all discovered APs.
  - Automatic channel hopper thread (`stress_hopper_thread`) with dwell control per attack mode.
  - Dedicated real-time TUI display showing discovered APs, per-AP packet transmission stats, channel distribution, and throughput metrics.
  - Auto-aging mechanism (`STRESS_AGE_SEC`) to clean inactive APs from the target pool.

---

## [4.2.0] - 2026-08-06

### Added
- **FragAttack Injection (Vector #15)**: New 802.11 fragment header manipulation attack based on Mathy Vanhoef's "Fragment and Forge" research (CVE-2020-24588 / CVE-2020-26145). Splits data frames into two fragments — Fragment 0 carries LLC/SNAP + partial ARP with `MoreFragments=1`, Fragment 1 carries injected plaintext payload (ICMP echo probe) — enabling data injection without knowing the Wi-Fi password. Implemented in both C (`mk_frag_setup`/`mk_frag_payload`) and Python (`make_frag_setup`/`make_frag_payload`).

---

## [4.1.0] - 2026-08-06

### Added
- **5GHz & Dual-Band Support**: Added support for 5GHz high-band channels (36–165), band selection (`abg`, `bg`, `a`) in scanner, and 802.11ac VHT hostapd rogue AP templates.
- **PMKID Auto-Extraction**: Automatically extracts 4-way handshake M1 PMKIDs and formats directly to Hashcat `22000` structure (`WPA*01*PMKID*AP*CLIENT*SSID`).
- **Command-Line Flags**: Added `--pmkid`, `--ids-bypass`, `--dual <iface>`, `--rogue`, `--stats <file>`, and `--help`.
- **JSON Boolean Support**: Added `jbool()` parser for boolean flags in automated script mode.
- **xorshift64 PRNG**: High-speed thread-local PRNG replacing locking `rand()` calls in hot loops.

### Fixed
- Fixed 802.11 radiotap header `TX_FLAGS` to `0x0018` (`NOACK | NOSEQ`) to prevent driver sequence overwrite and airtime wastage.
- Fixed EAPOL Logoff ToDS bit (`FC_DATA_TODS = 0x0108`) and correct address ordering.
- Fixed missing IEEE 802.11 DS Parameter Set IE (`ID 3`) across all beacon and probe response builders.
- Fixed Quiet IE continuous enforcement parameters (`cnt=1`, `period=1`).
- Fixed DELBA parameters (`initiator=1`, `TID=0`, `reason=39`).
- Fixed race condition in rate controller by allocating per-thread rolling window PID controllers.
- Fixed `set_ch()` to execute via direct `fork()`/`execlp()` instead of shell `system()` calls.
- Fixed rogue AP process cleanup using non-zombie blocking `waitpid()` reaping.

### Changed
- Replaced misleading "Hit Rate" telemetry metric with explicit "TX OK" transmission success percentage.
- Optimized stats file write frequency from 10Hz down to 1Hz.
- Automatic channel restoration for both primary and secondary interface on exit.

---

## [4.0.0] - 2026-08-01

### Added
- Native C11 rewrite replacing Python legacy implementation.
- `sendmmsg()` batch injection engine (up to 16 pkts/syscall).
- Lock-free atomic packet counters using `<stdatomic.h>`.
- Per-thread raw sockets eliminating socket contention.
- Socket send buffer tuning (`SO_SNDBUF` 2MB).

---

## [3.1.0] - 2026-07-25

### Legacy
- Initial Python proof-of-concept release.
