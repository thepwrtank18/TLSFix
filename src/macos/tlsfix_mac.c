// tlsfix (macOS) — route legacy Mac OS X Secure Transport HTTPS through mbedTLS (modern TLS 1.2/1.3).
//
// Mac OS X 10.6-10.11's Secure Transport can't handshake modern servers (old ciphers/curves, and
// its trust store no longer recognises today's certificate chains — e.g. the Mac App Store shows
// "cannot verify a secure connection"). CFNetwork drives an SSLContextRef via the SSL* C API. We
// keep the REAL SSLContextRef (so any SSL* we don't hook still operates on a valid context and
// can't crash) and attach an mbedTLS "shadow" that does the actual crypto: our hooks for the
// behavioural functions (handshake / read / write / state / trust) use the shadow, while CFNetwork
// keeps doing the sockets via the SSLReadFunc/SSLWriteFunc it installed.
//
// Platform glue:
//   * injection: DYLD_INSERT_LIBRARIES (system-wide via /etc/launchd.conf)
//   * hooking:   fishhook symbol rebinding (cross-image CFNetwork->Security calls)
//   * config:    CoreFoundation reads /Library/Preferences/com.tlsfix.plist
//   * safety:    a process denylist (boot/security-critical daemons)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <dispatch/dispatch.h>
#include <Block.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "fishhook.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"
#include "psa/crypto.h"     // TLS 1.3 in mbedTLS 3.x runs through PSA

#ifndef MBEDTLS_ERR_NET_RECV_FAILED
#define MBEDTLS_ERR_NET_RECV_FAILED -0x004C
#endif
#ifndef MBEDTLS_ERR_NET_SEND_FAILED
#define MBEDTLS_ERR_NET_SEND_FAILED -0x004E
#endif

// Logging is OFF by default (gDebug, the "debug" pref). Goes to syslog (visible in Console.app /
// `syslog` / `log`), gated to a single branch unless explicitly turned on in the prefs plist.
#define slog(fmt, ...) do { if (gDebug) syslog(LOG_NOTICE, "TLSFix| " fmt, ##__VA_ARGS__); } while (0)

// ---- Secure Transport constants (stable across OS X) ------------------------
#ifndef errSSLWouldBlock
#define errSSLWouldBlock      -9803
#endif
#define ST_ClosedGraceful     -9805
#define ST_ClosedAbort        -9806
#define ST_Connected           2     /* kSSLConnected (SSLSessionState) */
#define ST_TLS12               8     /* kTLSProtocol12 (SSLProtocol) */

// ---- shadow state ----------------------------------------------------------
typedef struct {
    SSLContextRef       ctx;
    SSLReadFunc         rf;
    SSLWriteFunc        wf;
    SSLConnectionRef    conn;
    char                host[256];
    int                 inited;     // mbedTLS objects set up
    int                 state;      // 0 none, 1 handshaking, 2 connected, -1 bypass
    int                 clientCert; // app set a client identity (mutual TLS) -> use system TLS
    unsigned            lastUse;    // for LRU eviction backstop
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
} Shadow;

#define MAXSH 256
static Shadow *gTab[MAXSH];
static unsigned gClock = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static mbedtls_ctr_drbg_context gDrbg;
static mbedtls_entropy_context  gEntropy;
static int gDrbgReady = 0;
static pthread_mutex_t gRng = PTHREAD_MUTEX_INITIALIZER;

static mbedtls_x509_crt gCA;        // modern Mozilla root bundle
static int gCAok = 0;
// Files live under /usr/lib: it's the one directory every process (incl. sandboxed daemons such as
// coreaudiod and the App Store's store* helpers) can read, because system.sb grants file-read* there
// for libSystem. /Library is NOT readable from most daemon sandboxes (dyld would abort the process
// trying to load an inserted lib it can't read), so the dylib and CA bundle must be here.
#define CA_PATH "/usr/lib/tlsfix-cacert.pem"
#define PREFS_PATH  "/Library/Preferences/com.tlsfix.plist"  // normal apps read this
#define PREFS_PATH2 "/usr/lib/tlsfix.plist"                  // sandbox-readable fallback for daemons

// CoreFoundation callback structs are DATA symbols. The dylib is injected dependency-free (only
// libSystem) so CF/Security resolve at runtime via dynamic_lookup — but dyld binds data symbols at
// LOAD time and can't find them in the flat namespace of an inserted lib. So resolve these two via
// dlsym during lazy init (by then Security, hence CoreFoundation, is loaded) instead of linking them.
static const CFArrayCallBacks *gArrCB = NULL;
static const CFSetCallBacks   *gSetCB = NULL;

// ---- global toggles (com.tlsfix.plist, read once at init; default ON) -------
static int gAllowTLS13  = 1;  // key "tls13": allow negotiating TLS 1.3 (off -> cap at 1.2)
static int gDrainGuard  = 1;  // key "drainGuard": bound the post-handshake drain loop (safety)
static int gSysFallback = 1;  // key "systemFallback": on mbedTLS handshake fail, retry host on the system's own stack
static int gDebug       = 0;  // key "debug": syslog handshake/SNI lines (OFF by default)
#define DRAIN_MAX 64          // iteration cap when gDrainGuard is on

// SecTrustRefs we built (already verified by mbedTLS) -> rubber-stamp their SecTrustEvaluate,
// since legacy SecTrust can't validate modern (esp. ECDSA) chains. The set RETAINS members
// (kCFTypeSetCallBacks) so a pointer can't be freed+reused while tracked (no false positives);
// bounded to the 64 most-recent via a ring that releases the evicted one.
static CFMutableSetRef gTrustSet = NULL;     // retains members
static void *gTrustRing[64];
static int gTrustIdx = 0;
static pthread_mutex_t gTrustLock = PTHREAD_MUTEX_INITIALIZER;
static void trust_remember(void *t) {
    pthread_mutex_lock(&gTrustLock);
    void *old = gTrustRing[gTrustIdx % 64];
    if (old && gTrustSet) CFSetRemoveValue(gTrustSet, old);   // release the evicted
    gTrustRing[gTrustIdx % 64] = t; gTrustIdx++;
    if (gTrustSet) CFSetAddValue(gTrustSet, t);               // retains t
    pthread_mutex_unlock(&gTrustLock);
}
static int trust_is_mine(void *t) {
    if (!gTrustSet) return 0;
    pthread_mutex_lock(&gTrustLock);
    int f = CFSetContainsValue(gTrustSet, t);
    pthread_mutex_unlock(&gTrustLock);
    return f;
}

// SHA-256 of leaf certs that mbedTLS already verified against the modern CA bundle.
// Some apps (notably iTunes) don't reuse the SecTrust we hand back via SSLCopyPeerTrust;
// their custom networking pulls the peer chain via SSLCopyPeerCertificates and builds their
// OWN SecTrust, which never lands in gTrustSet. Legacy SecTrustEvaluate then can't validate
// the modern chain -> "can't verify a secure connection". We additionally rubber-stamp any
// SecTrust whose LEAF was one we already verified. Matching the exact leaf DER (by hash) keeps
// this safe: we only vouch for certs mbedTLS validated, not arbitrary ones.
static unsigned char gVerLeaf[64][32];
static int gVerLeafIdx = 0;
static pthread_mutex_t gVerLeafLock = PTHREAD_MUTEX_INITIALIZER;
static void verleaf_remember(const unsigned char *der, size_t len) {
    if (!der || !len) return;
    unsigned char h[32];
    if (mbedtls_sha256(der, len, h, 0) != 0) return;
    pthread_mutex_lock(&gVerLeafLock);
    memcpy(gVerLeaf[gVerLeafIdx % 64], h, 32); gVerLeafIdx++;
    pthread_mutex_unlock(&gVerLeafLock);
}
static int verleaf_known(const unsigned char *der, size_t len) {
    if (!der || !len) return 0;
    unsigned char h[32];
    if (mbedtls_sha256(der, len, h, 0) != 0) return 0;
    int f = 0;
    pthread_mutex_lock(&gVerLeafLock);
    for (int i = 0; i < 64; i++) { if (memcmp(gVerLeaf[i], h, 32) == 0) { f = 1; break; } }
    pthread_mutex_unlock(&gVerLeafLock);
    return f;
}

// Hosts whose mbedTLS handshake failed — e.g. a server that only speaks TLS 1.0/1.1, which
// mbedTLS 3.x dropped, or any handshake mbedTLS can't complete. Their NEXT connection is routed
// to the system's own Secure Transport (which still does 1.0/1.1). In-memory ring (self-heals on
// app relaunch), so a one-off transient failure can't permanently pin a host to the legacy stack.
static char gFailHosts[64][256];
static int gFailIdx = 0;
static pthread_mutex_t gFailLock = PTHREAD_MUTEX_INITIALIZER;
static int host_is_failed(const char *h) {
    if (!h || !h[0]) return 0;
    int f = 0;
    pthread_mutex_lock(&gFailLock);
    for (int i = 0; i < 64; i++) if (gFailHosts[i][0] && strcmp(gFailHosts[i], h) == 0) { f = 1; break; }
    pthread_mutex_unlock(&gFailLock);
    return f;
}
static void host_mark_failed(const char *h) {
    if (!h || !h[0] || host_is_failed(h)) return;
    pthread_mutex_lock(&gFailLock);
    strncpy(gFailHosts[gFailIdx % 64], h, 255); gFailHosts[gFailIdx % 64][255] = 0;
    gFailIdx++;
    pthread_mutex_unlock(&gFailLock);
}

static int rng_cb(void *p, unsigned char *out, size_t len) {
    (void)p;
    pthread_mutex_lock(&gRng);
    int rc = mbedtls_ctr_drbg_random(&gDrbg, out, len);
    pthread_mutex_unlock(&gRng);
    return rc;
}

static int ensure_ready(void);          // per-process gate (cached pthread_once load after first call)

static void sh_destroy(Shadow *s) {     // caller must not hold gLock
    if (!s) return;
    if (s->inited) { mbedtls_ssl_free(&s->ssl); mbedtls_ssl_config_free(&s->conf); }
    free(s);
}
static Shadow *sh_get(SSLContextRef c) {
    // Fast bail for processes where tlsfix isn't active: skip the locked table scan entirely.
    if (ensure_ready() != 1) return NULL;
    Shadow *r = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { r = gTab[i]; r->lastUse = ++gClock; break; }
    pthread_mutex_unlock(&gLock);
    return r;
}
static Shadow *sh_create(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s) return s;
    s = (Shadow *)calloc(1, sizeof(Shadow));
    s->ctx = c;
    Shadow *evicted = NULL;
    pthread_mutex_lock(&gLock);
    int slot = -1;
    for (int i = 0; i < MAXSH; i++) if (!gTab[i]) { slot = i; break; }
    if (slot < 0) {                                  // table full -> evict least-recently-used
        int lru = 0; for (int i = 1; i < MAXSH; i++) if (gTab[i]->lastUse < gTab[lru]->lastUse) lru = i;
        evicted = gTab[lru]; slot = lru;
    }
    s->lastUse = ++gClock;
    gTab[slot] = s;
    pthread_mutex_unlock(&gLock);
    if (evicted) sh_destroy(evicted);
    return s;
}
static void sh_free(SSLContextRef c) {       // detach under lock, destroy outside it
    if (ensure_ready() != 1) return;         // inactive process never created shadows -> nothing to scan
    Shadow *s = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; gTab[i] = NULL; break; }
    pthread_mutex_unlock(&gLock);
    sh_destroy(s);
}

// ---- mbedTLS bio bridged to CFNetwork's SSLReadFunc/SSLWriteFunc -----------
static int bio_send(void *p, const unsigned char *buf, size_t len) {
    Shadow *s = (Shadow *)p;
    size_t n = len;
    OSStatus os = s->wf(s->conn, buf, &n);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock) return MBEDTLS_ERR_SSL_WANT_WRITE;
    return MBEDTLS_ERR_NET_SEND_FAILED;
}
static int bio_recv(void *p, unsigned char *buf, size_t len) {
    Shadow *s = (Shadow *)p;
    size_t n = len;
    OSStatus os = s->rf(s->conn, buf, &n);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock) return MBEDTLS_ERR_SSL_WANT_READ;
    if (os == ST_ClosedGraceful) return 0;
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

static int mbed_init(Shadow *s) {
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    int ret = mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) return ret;
    if (gCAok) {
        mbedtls_ssl_conf_ca_chain(&s->conf, &gCA, NULL);
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);  // real verify vs modern roots
    } else {
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);      // fallback if bundle missing
    }
    mbedtls_ssl_conf_rng(&s->conf, rng_cb, NULL);
    mbedtls_ssl_conf_min_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_2);   // refuse 1.0/1.1
    mbedtls_ssl_conf_max_tls_version(&s->conf, gAllowTLS13 ? MBEDTLS_SSL_VERSION_TLS1_3
                                                           : MBEDTLS_SSL_VERSION_TLS1_2);   // 1.3 preferred (toggle), negotiates down
    if ((ret = mbedtls_ssl_setup(&s->ssl, &s->conf))) return ret;
    if (s->host[0]) mbedtls_ssl_set_hostname(&s->ssl, s->host);
    mbedtls_ssl_set_bio(&s->ssl, s, bio_send, bio_recv, NULL);
    s->inited = 1;
    return 0;
}

// ---- hooks -----------------------------------------------------------------
static OSStatus (*o_SetIOFuncs)(SSLContextRef, SSLReadFunc, SSLWriteFunc);
static OSStatus my_SetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (ensure_ready() != 1) return o_SetIOFuncs(c, rf, wf);   // per-process gate (lazy)
    OSStatus r = o_SetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c); s->rf = rf; s->wf = wf;
    return r;
}
static OSStatus (*o_SetConnection)(SSLContextRef, SSLConnectionRef);
static OSStatus my_SetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (ensure_ready() != 1) return o_SetConnection(c, conn);
    OSStatus r = o_SetConnection(c, conn);
    Shadow *s = sh_create(c); s->conn = conn;
    return r;
}
static OSStatus (*o_SetPeerDomainName)(SSLContextRef, const char *, size_t);
static OSStatus my_SetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (ensure_ready() != 1) return o_SetPeerDomainName(c, name, len);
    OSStatus r = o_SetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);     // may be called before SSLSetIOFuncs -> create here too
    if (name && len) {
        size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
        // Strip trailing dot(s): callers (e.g. iTunes) sometimes pass the fully-qualified form
        // 'host.' which won't match the cert CN/SAN 'host', failing mbedTLS hostname verification.
        while (n > 0 && s->host[n - 1] == '.') s->host[--n] = 0;
        // if the handshake already started without SNI, restart it WITH the hostname
        if (s->inited && s->state != -1) {
            slog("late SNI '%s' -> re-init handshake", s->host);
            mbedtls_ssl_free(&s->ssl); mbedtls_ssl_config_free(&s->conf);
            s->inited = 0; s->state = 0;
        }
        slog("SetPeerDomainName ctx=%p '%s'", (void *)c, s->host);
    }
    return r;
}

// best-effort host for diagnostics, even on contexts we never shadowed (reads the SNI the caller set)
static void log_unshadowed(SSLContextRef c, Shadow *s, const char *reason) {
    if (!gDebug) return;
    char hn[256] = {0}; size_t hl = sizeof(hn) - 1;
    if (s && s->host[0]) { snprintf(hn, sizeof(hn), "%s", s->host); }
    else { extern OSStatus SSLGetPeerDomainName(SSLContextRef, char *, size_t *); if (SSLGetPeerDomainName(c, hn, &hl) != noErr) hn[0] = 0; }
    slog("real SSLHandshake (unshadowed) ctx=%p host='%s' reason=%s", (void *)c, hn, reason);
}
static OSStatus (*o_Handshake)(SSLContextRef);
static OSStatus my_Handshake(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (!s || !s->rf || !s->wf || !s->conn || s->clientCert) {                       // can't shim -> system
        log_unshadowed(c, s, !s ? "no-shadow" : s->clientCert ? "clientCert" : (!s->rf || !s->wf) ? "no-iofuncs" : "no-conn");
        return o_Handshake(c);
    }
    if (s->state == -1) return o_Handshake(c);
    if (gSysFallback && host_is_failed(s->host)) { log_unshadowed(c, s, "host-prev-failed"); s->state = -1; return o_Handshake(c); }  // known mbedTLS-incompatible -> system stack
    if (!s->inited) {
        int mi = mbed_init(s); if (mi) { s->state = -1; slog("mbed_init failed (-0x%x) for %s -> system TLS", -mi, s->host); return o_Handshake(c); }
        s->state = 1;
        slog("mbedTLS handshake start: %s", s->host[0] ? s->host : "(no SNI)");
    }
    int ret = mbedtls_ssl_handshake(&s->ssl);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (ret == 0) {
        s->state = 2;
        // remember this verified leaf so we'll also stamp an app-built SecTrust over the same cert
        if (gCAok) { const mbedtls_x509_crt *pc = mbedtls_ssl_get_peer_cert(&s->ssl); if (pc) verleaf_remember(pc->raw.p, pc->raw.len); }
        slog("mbedTLS handshake OK: %s [%s] (%s)", s->host, mbedtls_ssl_get_version(&s->ssl), mbedtls_ssl_get_ciphersuite(&s->ssl));
        return noErr;
    }
    char eb[128] = {0}; mbedtls_strerror(ret, eb, sizeof(eb));
    slog("mbedTLS handshake FAIL %s: %s (-0x%x)%s", s->host, eb, -ret, gSysFallback ? " -> system stack on retry" : "");
    // ClientHello already went out on this socket, so we can't cleanly hand THIS connection to the
    // system stack — remember the host so its next connection bypasses to the system Secure Transport.
    if (gSysFallback) host_mark_failed(s->host);
    s->state = -1;
    return ST_ClosedAbort;
}

static OSStatus (*o_Read)(SSLContextRef, void *, size_t, size_t *);
static OSStatus my_Read(SSLContextRef c, void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) return o_Read(c, data, len, processed);
    *processed = 0;
    int n, guard = 0;
    for (;;) {
        n = mbedtls_ssl_read(&s->ssl, (unsigned char *)data, len);
        // TLS 1.3 delivers post-handshake messages (NewSessionTicket / KeyUpdate) inline;
        // mbedTLS surfaces them as these "errors" — keep reading until application data.
        if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA
        if (n == MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA) continue;
#endif
        // mbedTLS can read a whole record off the transport yet return WANT_READ without
        // surfacing app data (a post-handshake message only half-processed). CFNetwork is
        // event-driven on the SOCKET and won't re-enter SSLRead until the socket is readable —
        // but those bytes are already drained into mbedTLS, so the socket never wakes again =>
        // permanent hang (rampant in TLS 1.3 due to NewSessionTickets). Drain everything mbedTLS
        // can process without touching the socket before we yield WouldBlock.
        if ((n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            && mbedtls_ssl_check_pending(&s->ssl) && (!gDrainGuard || ++guard < DRAIN_MAX)) continue;
        break;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return ST_ClosedGraceful;
    if (n < 0) return ST_ClosedAbort;
    *processed = (size_t)n;
    return noErr;
}
static OSStatus (*o_Write)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus my_Write(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) return o_Write(c, data, len, processed);
    *processed = 0;
    int n = mbedtls_ssl_write(&s->ssl, (const unsigned char *)data, len);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (n < 0) return ST_ClosedAbort;
    *processed = (size_t)n;
    return noErr;
}
static OSStatus (*o_DisposeContext)(SSLContextRef);
static OSStatus my_DisposeContext(SSLContextRef c) { sh_free(c); return o_DisposeContext(c); }
static OSStatus (*o_Close)(SSLContextRef);
static OSStatus my_Close(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) mbedtls_ssl_close_notify(&s->ssl);
    return o_Close(c);
}
static OSStatus (*o_GetSessionState)(SSLContextRef, SSLSessionState *);
static OSStatus my_GetSessionState(SSLContextRef c, SSLSessionState *st) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (st) *st = ST_Connected; return noErr; }
    return o_GetSessionState(c, st);
}
static OSStatus (*o_GetNegProto)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetNegProto(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (p) *p = ST_TLS12; return noErr; }
    return o_GetNegProto(c, p);
}
// SSLGetProtocolVersion — the deprecated configured-version getter; report TLS12 for shimmed conns.
static OSStatus (*o_GetProtoVer)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetProtoVer(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (p) *p = ST_TLS12; return noErr; }
    return o_GetProtoVer(c, p);
}
// SSLGetNegotiatedCipher — the real SSLContext never handshook (mbedTLS did), so without this an
// app querying the cipher gets garbage. SSLCipherSuite IS the IANA cipher-suite number.
//
// BUT: legacy clients validate the negotiated cipher against the suites their SecureTransport knows.
// iTunes' CommerceKit does exactly this for its "is this a secure connection with the iTunes Store?"
// gate — and our modern suites (TLS 1.3 0x13xx, ECDHE-GCM 0xC02B+, ChaCha 0xCCxx) don't exist in the
// 10.8 enum, so it reports "can't verify a secure connection (11311)" even though the connection is
// fine. Report a strong, 10.8-recognized TLS 1.2 ECDHE suite for those (we already report the version
// as TLS 1.2); mbedTLS still does the real crypto. Genuinely-old suites pass through unchanged.
#define ST_CIPHER_COMPAT 0xC014u   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA — known since 10.6 */
static int cipher_is_modern(UInt32 cs) {
    return ((cs & 0xFF00u) == 0x1300u)            // TLS 1.3 suites
        || (cs >= 0xC02Bu && cs <= 0xC032u)       // ECDHE_{RSA,ECDSA}_*_GCM_*
        || (cs >= 0xCCA8u && cs <= 0xCCAAu);      // ECDHE_*_CHACHA20_POLY1305
}
static OSStatus (*o_GetNegCipher)(SSLContextRef, UInt32 *);
static OSStatus my_GetNegCipher(SSLContextRef c, UInt32 *cipher) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) {
        UInt32 real = (UInt32)mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl);
        UInt32 rep  = cipher_is_modern(real) ? ST_CIPHER_COMPAT : real;
        if (cipher) *cipher = rep;
        slog("GetNegotiatedCipher: real=0x%04x report=0x%04x", real, rep);
        return noErr;
    }
    return o_GetNegCipher(c, cipher);
}
static OSStatus (*o_GetBuffered)(SSLContextRef, size_t *);
static OSStatus my_GetBuffered(SSLContextRef c, size_t *sz) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) {
        // Only report genuinely-decrypted application data waiting. (check_pending would count
        // *any* buffered record incl. TLS1.3 NewSessionTickets, which would make CFNetwork SSLRead
        // expect data it can't get -> unsound.)
        size_t avail = mbedtls_ssl_get_bytes_avail(&s->ssl);
        if (sz) *sz = avail;
        return noErr;
    }
    return o_GetBuffered(c, sz);
}

// build a CFArray of SecCertificateRef from the chain mbedTLS actually received (+1, caller owns)
static CFArrayRef sh_cert_array(Shadow *s) {
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&s->ssl);
    if (!crt) return NULL;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, gArrCB);
    for (const mbedtls_x509_crt *p = crt; p; p = p->next) {
        CFDataRef d = CFDataCreate(NULL, p->raw.p, p->raw.len);
        SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
        if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
        if (d) CFRelease(d);
    }
    return arr;
}

// peer trust: hand CFNetwork a SecTrust built from the cert chain mbedTLS actually saw. Returns 1
// and sets *trust (+1, caller owns) on success; 0 if the caller should fall back to the system.
// Shared by both the modern (SSLCopyPeerTrust) and legacy (SSLGetPeerSecTrust) entry points.
static int sh_build_trust(Shadow *s, SecTrustRef *trust) {
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return 0;
    CFStringRef hostStr = s->host[0] ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    SecPolicyRef pol = SecPolicyCreateSSL(true, hostStr);
    if (hostStr) CFRelease(hostStr);
    SecTrustRef t = NULL;
    OSStatus r = SecTrustCreateWithCertificates(arr, pol, &t);
    if (pol) CFRelease(pol);
    CFRelease(arr);
    if (r == errSecSuccess) { trust_remember(t); *trust = t; return 1; }
    return 0;
}
static OSStatus (*o_CopyPeerTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_CopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !trust) return o_CopyPeerTrust(c, trust);
    if (sh_build_trust(s, trust)) return noErr;
    return o_CopyPeerTrust(c, trust);
}
// SSLGetPeerSecTrust — the older name for SSLCopyPeerTrust (same semantics: caller releases).
static OSStatus (*o_GetPeerSecTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_GetPeerSecTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !trust) return o_GetPeerSecTrust(c, trust);
    if (sh_build_trust(s, trust)) return noErr;
    return o_GetPeerSecTrust(c, trust);
}

// apps that read the chain directly (not via SSLCopyPeerTrust) must get mbedTLS's real chain,
// not the un-handshaked real context's (empty) one.
static OSStatus (*o_CopyPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_CopyPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !certs) return o_CopyPeerCerts(c, certs);
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return o_CopyPeerCerts(c, certs);
    *certs = arr;   // +1, caller owns
    return noErr;
}
// SSLGetPeerCertificates — the deprecated name. Unlike SSLCopyPeerCertificates, its documented
// contract is that the caller releases the array AND each certificate, so hand back an extra retain
// per element to balance (otherwise an old, correct caller over-releases -> crash).
static OSStatus (*o_GetPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_GetPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !certs) return o_GetPeerCerts(c, certs);
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return o_GetPeerCerts(c, certs);
    for (CFIndex i = 0, n = CFArrayGetCount(arr); i < n; i++) CFRetain(CFArrayGetValueAtIndex(arr, i));
    *certs = arr;
    return noErr;
}

// client cert / mutual TLS: we can't export the (often non-extractable) private key into mbedTLS,
// so mark the connection and let it fall back to the system TLS stack (Apple servers accept old TLS
// from their own clients — push/iCloud keep working, just not upgraded).
static OSStatus (*o_SetCertificate)(SSLContextRef, CFArrayRef);
static OSStatus my_SetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (ensure_ready() != 1) return o_SetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    s->clientCert = 1;
    slog("SSLSetCertificate -> client cert, bypass to system TLS");
    return o_SetCertificate(c, certRefs);
}

// mbedTLS already verified the chain+hostname against the modern bundle; tell CFNetwork the trust
// is valid (legacy SecTrust would otherwise reject modern/ECDSA chains).
// We stamp a SecTrust iff it's one we built (in gTrustSet) OR its leaf is a cert mbedTLS just
// verified (apps like iTunes build their own SecTrust from the chain we hand back).
static int trust_should_stamp(SecTrustRef t) {
    if (!gCAok || !t) return 0;
    if (trust_is_mine((void *)t)) return 1;
    SecCertificateRef leaf = SecTrustGetCertificateAtIndex(t, 0);
    if (!leaf) return 0;
    CFDataRef d = SecCertificateCopyData(leaf);
    if (!d) return 0;
    int known = verleaf_known(CFDataGetBytePtr(d), (size_t)CFDataGetLength(d));
    CFRelease(d);
    return known;
}
static OSStatus (*o_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus my_SecTrustEvaluate(SecTrustRef t, SecTrustResultType *res) {
    if (trust_should_stamp(t)) { if (res) *res = kSecTrustResultUnspecified; return errSecSuccess; }
    OSStatus r = o_SecTrustEvaluate(t, res);
    if (gCAok && t) slog("SecTrustEvaluate: passthrough t=%p -> r=%d res=%d", (void *)t, (int)r, res ? (int)*res : -1);
    return r;
}

// CFNetwork (incl. iTunes' in-process WebKit) evaluates server trust ASYNCHRONOUSLY via this SPI,
// so the sync hook above never fires for it — the legacy evaluator then fails the modern chain and
// iTunes shows "a secure network connection could not be established". Stamp the same way, invoking
// the caller's completion block (on its queue) with kSecTrustResultUnspecified.
typedef void (^TLSFixTrustCB)(SecTrustRef, SecTrustResultType);
static OSStatus (*o_SecTrustEvaluateAsync)(SecTrustRef, dispatch_queue_t, TLSFixTrustCB);
static OSStatus my_SecTrustEvaluateAsync(SecTrustRef t, dispatch_queue_t q, TLSFixTrustCB cb) {
    if (cb && trust_should_stamp(t)) {
        slog("SecTrustEvaluateAsync: stamp t=%p", (void *)t);
        TLSFixTrustCB c = Block_copy(cb);          // outlive this frame
        SecTrustRef tr = (SecTrustRef)CFRetain(t); // keep trust alive until the callback runs
        dispatch_async(q ? q : dispatch_get_main_queue(), ^{
            c(tr, kSecTrustResultUnspecified);
            CFRelease(tr);
            Block_release(c);
        });
        return errSecSuccess;
    }
    if (gCAok && t) slog("SecTrustEvaluateAsync: passthrough t=%p", (void *)t);
    return o_SecTrustEvaluateAsync(t, q, cb);
}

// ---- hook table + installation (fishhook) ----------------------------------
static struct { const char *name; void *repl; void **orig; } gHooks[] = {
    {"SSLSetIOFuncs",                  (void *)my_SetIOFuncs,       (void **)&o_SetIOFuncs},
    {"SSLSetConnection",               (void *)my_SetConnection,    (void **)&o_SetConnection},
    {"SSLSetPeerDomainName",           (void *)my_SetPeerDomainName,(void **)&o_SetPeerDomainName},
    {"SSLHandshake",                   (void *)my_Handshake,        (void **)&o_Handshake},
    {"SSLRead",                        (void *)my_Read,             (void **)&o_Read},
    {"SSLWrite",                       (void *)my_Write,            (void **)&o_Write},
    {"SSLClose",                       (void *)my_Close,            (void **)&o_Close},
    {"SSLDisposeContext",              (void *)my_DisposeContext,   (void **)&o_DisposeContext},
    {"SSLGetSessionState",             (void *)my_GetSessionState,  (void **)&o_GetSessionState},
    {"SSLGetNegotiatedProtocolVersion",(void *)my_GetNegProto,      (void **)&o_GetNegProto},
    {"SSLGetBufferedReadSize",         (void *)my_GetBuffered,      (void **)&o_GetBuffered},
    {"SSLCopyPeerTrust",               (void *)my_CopyPeerTrust,    (void **)&o_CopyPeerTrust},
    {"SSLCopyPeerCertificates",        (void *)my_CopyPeerCerts,    (void **)&o_CopyPeerCerts},
    {"SSLSetCertificate",              (void *)my_SetCertificate,   (void **)&o_SetCertificate},
    {"SecTrustEvaluate",               (void *)my_SecTrustEvaluate, (void **)&o_SecTrustEvaluate},
    {"SecTrustEvaluateAsync",          (void *)my_SecTrustEvaluateAsync, (void **)&o_SecTrustEvaluateAsync},
    // deprecated / query variants (harmless if no image imports them)
    {"SSLGetPeerSecTrust",             (void *)my_GetPeerSecTrust,  (void **)&o_GetPeerSecTrust},
    {"SSLGetPeerCertificates",         (void *)my_GetPeerCerts,     (void **)&o_GetPeerCerts},
    {"SSLGetProtocolVersion",          (void *)my_GetProtoVer,      (void **)&o_GetProtoVer},
    {"SSLGetNegotiatedCipher",         (void *)my_GetNegCipher,     (void **)&o_GetNegCipher},
};
#define NHOOKS (sizeof(gHooks)/sizeof(gHooks[0]))

static void install_hooks(void) {
    struct rebinding rb[NHOOKS];
    for (size_t i = 0; i < NHOOKS; i++) {
        rb[i].name = gHooks[i].name;
        rb[i].replacement = gHooks[i].repl;
        rb[i].replaced = gHooks[i].orig;
    }
    rebind_symbols(rb, NHOOKS);
    // Backstop: ensure every "original" pointer is the real function even if fishhook didn't set it
    // (e.g. a symbol present in Security but not yet imported by any loaded image). Our hook bodies
    // call o_*(), so they must never be NULL when invoked.
    for (size_t i = 0; i < NHOOKS; i++) {
        if (*gHooks[i].orig == NULL) {
            void *real = dlsym(RTLD_DEFAULT, gHooks[i].name);
            if (real) *gHooks[i].orig = real;
        }
    }
}

// ---- config (CoreFoundation; no Foundation, to stay light in injected procs) ----
static CFDictionaryRef load_prefs_at(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) return NULL;
    CFDataRef data = NULL;
    SInt32 err = 0;
    Boolean ok = CFURLCreateDataAndPropertiesFromResource(NULL, url, &data, NULL, NULL, &err);
    CFRelease(url);
    if (!ok || !data) { if (data) CFRelease(data); return NULL; }
    CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data);
    if (plist && CFGetTypeID(plist) == CFDictionaryGetTypeID()) return (CFDictionaryRef)plist;
    if (plist) CFRelease(plist);
    return NULL;
}
static CFDictionaryRef load_prefs(void) {
    CFDictionaryRef d = load_prefs_at(PREFS_PATH);   // normal apps
    if (!d) d = load_prefs_at(PREFS_PATH2);          // sandboxed daemons (can't read /Library)
    return d;
}
static int pref_bool(CFDictionaryRef d, const char *key, int defv) {
    if (!d) return defv;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return defv;
    int r = defv;
    CFTypeRef v = CFDictionaryGetValue(d, k);
    if (v) {
        if (CFGetTypeID(v) == CFBooleanGetTypeID()) r = CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
        else if (CFGetTypeID(v) == CFNumberGetTypeID()) { int n = 0; CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &n); r = n ? 1 : 0; }
    }
    CFRelease(k);
    return r;
}

// ---- lazy activation -------------------------------------------------------
// Avoid heavy work in the constructor (it runs in EVERY injected
// process). The ctor only installs the (pure-C) symbol rebinds; the real init runs lazily on the
// first hook call, by which point the process is up. Inactive processes pass straight through.
static int g_state = 0;                          // 0 unchecked, 1 active, -1 disabled
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void do_ready(void) {
    // A hook has fired, so Security is now loaded even in lazy-loading processes. Resolve any
    // original pointers fishhook couldn't bind at constructor time, so o_*() are never NULL.
    for (size_t i = 0; i < NHOOKS; i++)
        if (*gHooks[i].orig == NULL) {
            void *real = dlsym(RTLD_DEFAULT, gHooks[i].name);
            if (real) *gHooks[i].orig = real;
        }
    CFDictionaryRef prefs = load_prefs();
    // per-process opt-out: "disable-<progname>" = true in the plist
    const char *pn = getprogname();
    if (pn && prefs) {
        char key[160]; snprintf(key, sizeof(key), "disable-%s", pn);
        if (pref_bool(prefs, key, 0)) { g_state = -1; if (prefs) CFRelease(prefs); return; }
    }
    gAllowTLS13  = pref_bool(prefs, "tls13", 1);
    gDrainGuard  = pref_bool(prefs, "drainGuard", 1);
    gSysFallback = pref_bool(prefs, "systemFallback", 1);
    gDebug       = pref_bool(prefs, "debug", 0);
    if (prefs) CFRelease(prefs);

    mbedtls_ctr_drbg_init(&gDrbg);
    mbedtls_entropy_init(&gEntropy);
    if (mbedtls_ctr_drbg_seed(&gDrbg, mbedtls_entropy_func, &gEntropy, (const unsigned char *)"tlsfix", 6) == 0)
        gDrbgReady = 1;
    psa_crypto_init();                              // TLS 1.3 path
    mbedtls_x509_crt_init(&gCA);
    gCAok = (mbedtls_x509_crt_parse_file(&gCA, CA_PATH) == 0);
    gArrCB = (const CFArrayCallBacks *)dlsym(RTLD_DEFAULT, "kCFTypeArrayCallBacks");
    gSetCB = (const CFSetCallBacks *)dlsym(RTLD_DEFAULT, "kCFTypeSetCallBacks");
    gTrustSet = CFSetCreateMutable(NULL, 0, gSetCB);
    g_state = 1;
    slog("active for %s (drbg=%d CA=%d tls13=%d drainGuard=%d sysFallback=%d)",
         pn ? pn : "?", gDrbgReady, gCAok, gAllowTLS13, gDrainGuard, gSysFallback);
}
static int ensure_ready(void) { pthread_once(&g_once, do_ready); return g_state; }

// blacklisted processes; doesn't need internet, if it does it needs to use the system stack
static int proc_is_denied(const char *pn) {
    if (!pn) return 1;
    static const char *deny[] = {
        "launchd", "launchctl", "kextd", "kextcache", "opendirectoryd", "securityd", "secd",
        "trustd", "configd", "syslogd", "aslmanager", "notifyd", "distnoted", "diskarbitrationd",
        "mds", "mds_stores", "mdworker", "mdflagwriter", "mDNSResponder", "mDNSResponderHelper",
        "coreservicesd", "installd", "install_monitored", "fseventsd", "hidd", "powerd",
        "loginwindow", "WindowServer", "dyld", "sh", "bash", "zsh", "ssh", "sshd", "scp",
        "sudo", "su", "login", "dtrace", "dtruss", "Terminal", 0
    };
    for (int i = 0; deny[i]; i++) if (strcmp(pn, deny[i]) == 0) return 1;
    return 0;
}

__attribute__((constructor))
static void tlsfix_init(void) {
    // pure C only here — no CoreFoundation/Security (those run lazily after the process is up).
    const char *pn = getprogname();
    if (proc_is_denied(pn)) return;
    // Install the rebinds UNCONDITIONALLY — do not gate on Security being loaded yet. Some targets
    // (App Store, SoftwareUpdateCheck, ...) link Security/CFNetwork LAZILY, after this constructor
    // runs; gating here meant their TLS silently fell through to the system stack. fishhook registers
    // a dyld add-image callback, so rebinding now also catches those frameworks whenever they load
    // later. The heavy init still happens lazily on the first hook call (see do_ready).
    install_hooks();
}
