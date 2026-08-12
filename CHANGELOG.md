# Changelog

All notable changes to the **VERITAS** framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.5.1] - 2026-08-10

### Fixed & Improved
- **High-Performance Atomics (Lock-Free)**: Replaced `pthread_mutex_t` locking in the stress mode packet counting logic with C11 hardware-level `_Atomic` operations (`__atomic_fetch_add` and `atomic_load`). This completely eliminates thread contention across the injector thread pool, allowing maximum packet injection rates (PPS) during Mass Injection.
- **Memory Integrity & Buffer Safety**: Removed deprecated `strcpy` function calls and replaced them with bounds-checked `snprintf`.
- **Advanced Radiotap Bounds Checking**: Hardened the `parse_radiotap_rssi` function with strict boundary checks against the `rt_len` packet length to prevent segmentation faults (Segfaults) when parsing corrupted or maliciously malformed beacon frames in the air.

---

## [4.6.0] - 2026-08-12

### Added
- **Native TX-Power & Regulatory Domain Unlocker**: When launched in `--insane` mode, Veritas now automatically manipulates the Linux network stack (`iw reg set BO` and `iwconfig txpower 30`) to force the Wi-Fi interface into Bolivia's regulatory domain and unlocks transmission power to the absolute hardware maximum of 1000mW (30dBm) for extreme attack range.
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
