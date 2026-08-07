# Changelog

All notable changes to the **VERITAS** framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
