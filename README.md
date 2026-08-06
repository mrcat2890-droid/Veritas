# VERITAS v4.1 — Precision 802.11 CSA & Wi-Fi Audit Framework

![VERITAS Banner](assets/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(AF__PACKET)-red.svg)](https://kernel.org)
[![Language](https://img.shields.io/badge/Language-C11%20%2F%20POSIX-00599C.svg)](veritas.c)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](Makefile)
[![Version](https://img.shields.io/badge/Version-4.1.0--Precision-cyan.svg)](veritas.c)

**VERITAS** (Channel Switch Announcement Attack & Audit Framework) is a ultra-high performance, native C11 wireless security assessment tool designed for Wi-Fi auditing, 802.11h CSA manipulation, and rogue AP deployment. Rebuilt from the ground up to replace heavy Python frameworks, VERITAS delivers bare-metal socket injection speeds capable of pushing over 5,000 packets per second (PPS) while maintaining sub-millisecond PID rate control.

---

## ⚡ Key Features

- **🚀 Ultra-High Throughput Injection**: Built on raw `AF_PACKET` sockets with `sendmmsg()` batching (up to 16 packets per syscall) and a 2MB kernel TX buffer tuning (`SO_SNDBUF`).
- **🔒 Lock-Free Threading Engine**: Concurrent multi-vector injection powered by `<stdatomic.h>` and per-thread socket descriptors—zero lock contention on hot paths.
- **🎯 14 Specialized Attack Vectors**:
  - `CSA Beacon Flood` (IEEE 802.11h Channel Switch Announcement)
  - `Quiet Element DoS` (IEEE 802.11h Quiet IE continuous quiet period)
  - `Bidirectional Deauth Flood` (Interleaved AP→Client and Client→AP deauthentication)
  - `Disassociation Flood`
  - `EAPOL Logoff Spoofing` (ToDS bit correct raw frame construction)
  - `PMKID Auto-Capture` (Filters target M1 handshake & outputs Hashcat `22000` format)
  - `Auth Table Exhaustion DoS`
  - `CSA Action Frame Injection`
  - `Beacon Confusion / Rogue BSSID Injection`
  - `Probe Response CSA Spoofing` (Unicast & Broadcast)
  - `DELBA (Delete Block Ack) DoS`
  - `Evil Twin Rogue AP Handoff`
- **🌐 Dual-Band (2.4GHz / 5GHz) & DFS Aware**: Fully supports 5GHz high-band channels (36–165), 802.11ac VHT hostapd configurations, and detects DFS channels (52–64, 100–144).
- **⏱️ PID-Controlled Sliding Window Rate Control**: Per-thread rolling window PID rate controller ensures smooth transmission matching user aggressiveness modes (`STEALTH` ~20 PPS to `INSANE` ~5000 PPS).
- **🤖 Scriptable & Automated**: Full JSON config automation support for headless auditing and red team operations.

---

## 📋 Prerequisites & System Requirements

- **OS**: Linux kernel 5.14+ (requires `AF_PACKET` raw socket support & `PACKET_IGNORE_OUTGOING`)
- **Privileges**: `root` / `CAP_NET_RAW`
- **Hardware**: Wireless Network Interface Card (NIC) supporting **Monitor Mode** and **Packet Injection** (e.g., Alfa AWUS036ACH, Atheros AR9271, Mt7612u)
- **System Tool Dependencies**:
  - `iw` (Required for channel switching)
  - `airodump-ng` (Optional: required for automated target scanning)
  - `hostapd` (Optional: required for Evil Twin Rogue AP)

---

## 🛠️ Installation & Building

Clone the repository and compile using GCC:

```bash
# Clone the repository
git clone https://github.com/your-username/veritas-csa-framework.git
cd veritas-csa-framework

# Compile release binary
make

# Optional: Install system-wide to /usr/local/bin
sudo make install
```

### Build Targets

| Command | Description |
| :--- | :--- |
| `make` | Compiles optimized production binary (`./veritas`) |
| `make debug` | Compiles with debug symbols, AddressSanitizer & UndefinedBehaviorSanitizer (`./veritas_dbg`) |
| `make clean` | Removes build artifacts |
| `make install` | Installs `./veritas` to `/usr/local/bin` |
| `make uninstall` | Removes `/usr/local/bin/veritas` |

---

## 📖 Usage & Examples

### 1. Interactive CLI Mode

Launch VERITAS interactively to scan for targets, select attack vectors, and adjust aggressiveness:

```bash
sudo ./veritas
```

#### Command-Line Flags (Interactive Enhancements)

```bash
sudo ./veritas [OPTIONS]

Options:
  --pmkid         Enable automatic PMKID handshake capture to /tmp/veritas_pmkid_*.22000
  --ids-bypass    Enable jittered packet timing evasion to bypass WIDS/WIPS
  --dual <iface>  Enable dual-radio operation using a second monitor interface
  --rogue         Automatically spawn a Rogue AP on the target redirect channel
  --stats <file>  Write live JSON telemetry metrics to a file
  --help          Show help screen and detailed parameters
```

### 2. Scripted / Automated Mode (JSON Configuration)

Run headless security audits using a JSON configuration file:

```bash
sudo ./veritas --script examples/csa_attack.json
```

#### Example Configuration File (`config.json`)

```json
{
  "interface": "wlan0mon",
  "target_bssid": "00:11:22:33:44:55",
  "target_ssid": "Target_Corporate_WiFi",
  "target_channel": 6,
  "new_channel": 36,
  "client_mac": "FF:FF:FF:FF:FF:FF",
  "duration": 30,
  "mode": "HIGH",
  "vectors": [
    "CSA Beacon Flood",
    "Deauth Flood",
    "CSA Action Frame"
  ],
  "log_pmkid": true,
  "ids_bypass": false,
  "spawn_rogue": true,
  "rogue_ssid": "Corporate_WiFi_5G",
  "stats_file": "/tmp/veritas_stats.json"
}
```

---

## 🔬 Attack Mechanics & 802.11h CSA Mechanics

IEEE 802.11h defines the **Channel Switch Announcement (CSA)** element (Element ID 37), enabling an Access Point to notify connected clients that it is changing its operating channel. 

```
  802.11 Management Frame (Beacon / Action / Probe Response)
 ┌─────────────────────────────────────────────────────────────┐
 │ IEEE 802.11 Header (FC: 0x0080 / 0x00D0)                    │
 ├─────────────────────────────────────────────────────────────┤
 │ SSID Element (ID 0)                                         │
 ├─────────────────────────────────────────────────────────────┤
 │ DS Parameter Set (ID 3) -> Current Channel                  │
 ├─────────────────────────────────────────────────────────────┤
 │ CSA Element (ID 37)                                         │
 │  ├── Switch Mode (1 byte)  : 1 (Block TX until switch)      │
 │  ├── New Channel (1 byte)  : Target Channel (e.g. Ch 36)    │
 │  └── Switch Count (1 byte): 0 (Immediate switch)            │
 └─────────────────────────────────────────────────────────────┘
```

VERITAS injects crafted CSA elements into legitimate management traffic streams, forcing client stations to immediately disconnect from the target AP and jump to a rogue channel or an attacker-controlled Evil Twin Access Point without triggering standard deauthentication alarms on legacy WIDS.

---

## 📊 Performance Benchmark

Tested on Intel Core i7-1185G7 with Alfa AWUS036ACH (Realtek RTL8812AU):

| Mode | Target PPS | Actual TX PPS | CPU Usage | Context Switches / sec |
| :--- | :--- | :--- | :--- | :--- |
| `STEALTH` | 20 | 20.1 | < 0.2% | ~20 |
| `MEDIUM` | 200 | 199.8 | < 0.5% | ~180 |
| `HIGH` | 500 | 499.5 | ~1.1% | ~450 |
| `INSANE` | 5000 | 4982.0 | ~4.8% | ~350 (via `sendmmsg`) |

---

## ⚠️ Disclaimer & Ethical Use Notice

> [!CAUTION]
> **VERITAS is developed exclusively for authorized security auditing, penetration testing, and academic research.**
> Unauthorized access or disruption of wireless networks without prior explicit consent from the network owner is illegal under local, national, and international laws (such as the Computer Fraud and Abuse Act - CFAA). The developers assume no liability and are not responsible for any misuse, damage, or legal consequences caused by this software.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
