# Changelog

All notable changes to the **VERITAS** framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
