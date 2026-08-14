# Changelog

All notable changes to the **VERITAS** framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
---

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
