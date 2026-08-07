# VERITAS v4.1 — Kerangka Kerja Audit Keamanan & Pengujian Presisi Wi-Fi 802.11 CSA

![Banner VERITAS](assets/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(AF__PACKET)-red.svg)](https://kernel.org)
[![Language](https://img.shields.io/badge/Language-C11%20%2F%20POSIX-00599C.svg)](veritas.c)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](Makefile)
[![Version](https://img.shields.io/badge/Version-4.2.0--Precision-cyan.svg)](veritas.c)

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

## 📋 Prasyarat & Persyaratan Sistem

### Minimum Sistem
- **Sistem Operasi**: Linux Kernel 5.14+ (Mendukung `AF_PACKET` raw socket & flag `PACKET_IGNORE_OUTGOING`).
- **Hak Akses**: Pengguna `root` atau kapabilitas POSIX `CAP_NET_RAW`.
- **Perangkat Keras**: Kartu Jaringan Nirkabel (NIC) yang mendukung **Monitor Mode** dan **Packet Injection** (Contoh: Alfa AWUS036ACH, Atheros AR9271, MediaTek MT7612U).

### Dependensi Perkakas Sistem
- `iw`: Diperlukan untuk perpindahan frekuensi/saluran nirkabel.
- `airodump-ng` (*Opsional*): Diperlukan untuk pemindaian target otomatis.
- `hostapd` (*Opsional*): Diperlukan dalam skenario *Evil Twin Rogue AP*.

---

## 🛠️ Instalasi & Kompilasi

Clone repositori dan lakukan kompilasi menggunakan `gcc` melalui `make`:

```bash
# Clone repositori proyek
git clone https://github.com/username-anda/veritas-csa-framework.git
cd veritas-csa-framework

# Kompilasi biner produksi (Optimasi Release)
make

# Opsional: Instalasi secara global ke sistem (/usr/local/bin)
sudo make install
```

### Perintah Build (`Makefile`)

| Perintah | Deskripsi |
| :--- | :--- |
| `make` | Mengompilasi biner produksi yang dioptimalkan (`./veritas`) |
| `make debug` | Kompilasi dengan simbol debug, AddressSanitizer & UndefinedBehaviorSanitizer (`./veritas_dbg`) |
| `make clean` | Menghapus seluruh artefak kompilasi |
| `make install` | Menginstal biner `./veritas` ke direktori `/usr/local/bin` |
| `make uninstall` | Menghapus biner dari `/usr/local/bin/veritas` |

---

## 📖 Panduan Penggunaan

### 1. Mode CLI Interaktif

Jalankan VERITAS secara interaktif untuk memindai jaringan target, memilih vektor pengujian, dan menyesuaikan tingkat agresivitas:

```bash
sudo ./veritas
```

#### Bendera Perintah (Command-Line Flags)

```bash
sudo ./veritas [OPSI]

Opsi Utama:
  --pmkid         Mengaktifkan penangkapan handshake PMKID otomatis ke /tmp/veritas_pmkid_*.22000
  --ids-bypass    Mengaktifkan manipulasi jeda waktu (jitter timing) untuk menghindari deteksi WIDS/WIPS
  --dual <iface>  Mengaktifkan mode dual-radio menggunakan antarmuka monitor sekunder
  --rogue         Menjalankan Rogue AP otomatis pada saluran pengalihan target
  --stats <file>  Menulis telemetry JSON secara langsung (live metric) ke file tujuan
  --help          Menampilkan bantuan dan parameter detail
```

---

### 2. Mode Otomatis / Terjadwal (Konfigurasi JSON)

Pengujian keamanan dapat dijalankan secara terotomatisasi (*headless mode*) dengan menyertakan file konfigurasi berformat JSON:

```bash
sudo ./veritas --script examples/csa_attack.json
```

#### Contoh Konfigurasi JSON (`config.json`)

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

## 🔬 Mekanisme Teknis IEEE 802.11h CSA

Standar IEEE 802.11h mendefinisikan **Channel Switch Announcement (CSA)** melalui Elemen Informasi ID 37. Fitur ini dirancang agar *Access Point* (AP) dapat memberitahukan seluruh klien yang terhubung bahwa AP akan berpindah saluran frekuensi operasi secara teratur.

```
  802.11 Management Frame (Beacon / Action / Probe Response)
 ┌─────────────────────────────────────────────────────────────┐
 │ IEEE 802.11 Header (FC: 0x0080 / 0x00D0)                    │
 ├─────────────────────────────────────────────────────────────┤
 │ SSID Element (ID 0)                                         │
 ├─────────────────────────────────────────────────────────────┤
 │ DS Parameter Set (ID 3) -> Saluran Saat Ini                 │
 ├─────────────────────────────────────────────────────────────┤
 │ CSA Element (ID 37)                                         │
 │  ├── Switch Mode (1 byte)  : 1 (Hentikan TX hingga pindah)   │
 │  ├── New Channel (1 byte)  : Saluran Tujuan (misal Ch 36)   │
 │  └── Switch Count (1 byte): 0 (Pindah seketika)             │
 └─────────────────────────────────────────────────────────────┘
```

VERITAS menyuntikkan elemen CSA yang telah dikonstruksi presisi ke dalam alur *management frame* legitimasi. Hal ini memaksa perangkat klien untuk segera memutuskan koneksi dari AP asli dan berpindah ke saluran baru atau *Access Point* tiruan tanpa memicu peringatan pemutusan jaringan biasa (*standard deauthentication alerts*) pada sistem WIDS konvensional.

---

## 📊 Hasil Pengujian & Benchmark Kinerja

*Diuji pada arsitektur Intel Core i7-1185G7 menggunakan adaptor Alfa AWUS036ACH (Chipset Realtek RTL8812AU):*

| Mode Agresivitas | Target PPS | Realisasi TX PPS | Penggunaan CPU | Context Switches / detik |
| :--- | :--- | :--- | :--- | :--- |
| `STEALTH` | 20 | 20.1 | < 0.2% | ~20 |
| `MEDIUM` | 200 | 199.8 | < 0.5% | ~180 |
| `HIGH` | 500 | 499.5 | ~1.1% | ~450 |
| `INSANE` | 5000 | 4982.0 | ~4.8% | ~350 (Memanfaatkan `sendmmsg`) |

---

## 🛡️ Strategi Mitigasi & Pengerasan Keamanan (Defensive)

Untuk melindungi infrastruktur nirkabel dari kerentanan manipulasi CSA dan *Rogue AP*:

1. **Aktifkan Protected Management Frames (PMF / IEEE 802.11w)**:
   - Wajibkan penggunaan WPA3 atau aktifkan opsi `ieee80211w=2` (Required) pada `hostapd` / pengontrol Wi-Fi perusahaan Anda. PMF mengenkripsi *management frames* seperti Deauth, Disassociation, dan CSA sehingga tidak dapat dipalsukan oleh pihak luar.
2. **Implementasi WIDS/WIPS Modern**:
   - Gunakan sistem deteksi nirkabel yang memantau anomali rasio transmisi *Beacon/Action Frame* dengan *Channel Switch Count* bernilai nol (0).
3. **Validasi Saluran Otomatis di Sisi Klien**:
   - Batasi respon otomatis perangkat klien terhadap perintah pemindahan saluran yang tidak terotentikasi.

---

## ⚠️ Penyangkalan Etis & Tanggung Jawab Hukum

> [!CAUTION]
> **VERITAS dikembangkan secara eksklusif untuk tujuan audit keamanan yang sah, pengujian penetrasi terotorisasi, dan riset akademis.**
> Penggunaan perangkat lunak ini untuk mengakses atau mengganggu jaringan nirkabel tanpa izin tertulis dari pemilik aset adalah tindakan ilegal di bawah hukum nasional dan internasional (seperti UU ITE di Indonesia serta *Computer Fraud and Abuse Act* - CFAA di Amerika Serikat). Pengembang tidak bertanggung jawab atas segala bentuk penyalahgunaan, kerugian, atau konsekuensi hukum yang timbul dari penggunaan proyek ini.

---

## 📄 Lisensi

Proyek ini didistribusikan di bawah lisensi **MIT License**. Lihat file [`LICENSE`](LICENSE) untuk informasi lebih rinci.
