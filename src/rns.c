/*
 * rns.c - a minimal Reticulum client
 *
 * Wire formats follow the Python reference implementation (RNS 1.x):
 * Packet.py, Identity.py, Link.py and Transport.py.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "rns.h"

#define HEADER_1 0
#define HEADER_2 1
#define TRANSPORT_BROADCAST 0
#define TRANSPORT_TRANSPORT 1

#define MODE_AES256_CBC 0x01
#define SIGNALLING_LEN 3

#define PATH_REQUEST_INTERVAL 15.0
#define PATH_TIMEOUT_DEFAULT 60.0
#define PER_HOP_TIMEOUT 6.0
#define KEEPALIVE_MAX 360.0
#define KEEPALIVE_MIN 5.0
#define KEEPALIVE_MAX_RTT 1.75
#define KEEPALIVE_TIMEOUT_FACTOR 4.0
#define STALE_FACTOR 2.0
#define STALE_GRACE 5.0

static const char *PATH_REQUEST_NAME = "rnstransport.path.request";
static const char *HUB_NAME = "rrc.hub";

/* ---- helpers ---- */

static void
clog_(struct rns_client *c, int level, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!c->cb.log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    c->cb.log(c->ctx, level, buf);
}

void
rns_hex(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

static int
hexval(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

int
rns_unhex(const char *in, uint8_t *out, size_t len)
{
    size_t i;
    int hi, lo;

    if (strlen(in) != 2 * len)
        return -1;
    for (i = 0; i < len; i++) {
        hi = hexval(in[2 * i]);
        lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

const char *
rns_state_name(enum rns_state state)
{
    switch (state) {
    case RNS_IDLE: return "idle";
    case RNS_PATH: return "finding path";
    case RNS_LINKING: return "linking";
    case RNS_ACTIVE: return "active";
    case RNS_CLOSED: return "closed";
    }
    return "?";
}

static void
truncated_hash(const uint8_t *data, size_t len, uint8_t out[RNS_HASH_LEN])
{
    uint8_t full[32];

    cr_sha256(data, len, full);
    memcpy(out, full, RNS_HASH_LEN);
}

/* ---- identities ---- */

int
rns_identity_from_bytes(struct rns_identity *id, const uint8_t prv[RNS_PRVKEY_LEN])
{
    memcpy(id->x_prv, prv, 32);
    memcpy(id->ed_seed, prv + 32, 32);
    if (cr_x25519_public(id->x_prv, id->pub) != 0
        || cr_ed25519_public(id->ed_seed, id->pub + 32) != 0)
        return -1;
    truncated_hash(id->pub, RNS_PUBKEY_LEN, id->hash);
    return 0;
}

int
rns_identity_generate(struct rns_identity *id)
{
    uint8_t prv[RNS_PRVKEY_LEN];
    int rc;

    if (cr_random(prv, sizeof(prv)) != 0)
        return -1;
    rc = rns_identity_from_bytes(id, prv);
    cr_wipe(prv, sizeof(prv));
    return rc;
}

int
rns_identity_load(struct rns_identity *id, const char *path)
{
    uint8_t prv[RNS_PRVKEY_LEN + 1];
    ssize_t n;
    int fd, rc;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, prv, sizeof(prv));
    close(fd);
    if (n != RNS_PRVKEY_LEN) {
        cr_wipe(prv, sizeof(prv));
        errno = EINVAL;
        return -1;
    }
    rc = rns_identity_from_bytes(id, prv);
    cr_wipe(prv, sizeof(prv));
    return rc;
}

int
rns_identity_save(const struct rns_identity *id, const char *path)
{
    uint8_t prv[RNS_PRVKEY_LEN];
    ssize_t n;
    int fd;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    memcpy(prv, id->x_prv, 32);
    memcpy(prv + 32, id->ed_seed, 32);
    n = write(fd, prv, sizeof(prv));
    cr_wipe(prv, sizeof(prv));
    if (n != RNS_PRVKEY_LEN || fsync(fd) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }
    return close(fd);
}

void
rns_name_hash(const char *name, uint8_t out[RNS_NAME_HASH_LEN])
{
    uint8_t full[32];

    cr_sha256((const uint8_t *)name, strlen(name), full);
    memcpy(out, full, RNS_NAME_HASH_LEN);
}

void
rns_destination_hash(const char *name, const uint8_t *identity_hash,
                     uint8_t out[RNS_HASH_LEN])
{
    uint8_t material[RNS_NAME_HASH_LEN + RNS_HASH_LEN];
    size_t n = RNS_NAME_HASH_LEN;

    rns_name_hash(name, material);
    if (identity_hash) {
        memcpy(material + n, identity_hash, RNS_HASH_LEN);
        n += RNS_HASH_LEN;
    }
    truncated_hash(material, n, out);
}

/* ---- packets ---- */

int
rns_packet_parse(const uint8_t *raw, size_t len, struct rns_packet *p)
{
    size_t off;

    memset(p, 0, sizeof(*p));
    if (len < RNS_HEADER_MINSIZE + 1 || len > RNS_MTU)
        return -1;
    p->raw = raw;
    p->raw_len = len;
    p->flags = raw[0];
    p->hops = raw[1];
    if (p->flags & 0x80)
        return -1;   /* IFAC: not supported on our interfaces */
    if (p->hops >= 128)
        return -1;
    p->header_type = (p->flags >> 6) & 0x01;
    p->context_flag = (p->flags >> 5) & 0x01;
    p->transport_type = (p->flags >> 4) & 0x01;
    p->dest_type = (p->flags >> 2) & 0x03;
    p->packet_type = p->flags & 0x03;
    off = 2;
    if (p->header_type == HEADER_2) {
        if (len < RNS_HEADER_MAXSIZE + 1)
            return -1;
        p->transport_id = raw + off;
        off += RNS_HASH_LEN;
    }
    p->dest = raw + off;
    off += RNS_HASH_LEN;
    p->context = raw[off++];
    p->data = raw + off;
    p->data_len = len - off;
    return p->data_len > 0 ? 0 : -1;
}

void
rns_packet_hash(const struct rns_packet *p, uint8_t out[32])
{
    uint8_t first = p->flags & 0x0f;
    size_t skip = p->header_type == HEADER_2 ? 2 + RNS_HASH_LEN : 2;

    cr_sha256_2(&first, 1, p->raw + skip, p->raw_len - skip, out);
}

static size_t
build_packet(uint8_t *out, uint8_t flags, uint8_t hops,
             const uint8_t *transport_id, const uint8_t *dest, uint8_t context,
             const uint8_t *data, size_t len)
{
    size_t n = 0;

    out[n++] = flags;
    out[n++] = hops;
    if (transport_id) {
        memcpy(out + n, transport_id, RNS_HASH_LEN);
        n += RNS_HASH_LEN;
    }
    memcpy(out + n, dest, RNS_HASH_LEN);
    n += RNS_HASH_LEN;
    out[n++] = context;
    memcpy(out + n, data, len);
    return n + len;
}

static uint8_t
make_flags(int header_type, int context_flag, int transport_type,
           int dest_type, int packet_type)
{
    return (uint8_t)((header_type << 6) | (context_flag << 5) | (transport_type << 4)
                     | (dest_type << 2) | packet_type);
}

static int
transmit(struct rns_client *c, const uint8_t *pkt, size_t len, double now)
{
    if (len > RNS_MTU)
        return -1;
    c->tx_packets++;
    c->last_outbound = now;
    return c->cb.send(c->ctx, pkt, len);
}

/* Remember a packet hash; returns 1 if it was already seen. */
static int
seen_before(struct rns_client *c, const struct rns_packet *p)
{
    uint8_t h[32];
    size_t i;

    rns_packet_hash(p, h);
    for (i = 0; i < c->seen_count; i++)
        if (memcmp(c->seen[i], h, RNS_HASH_LEN) == 0)
            return 1;
    memcpy(c->seen[c->seen_next], h, RNS_HASH_LEN);
    c->seen_next = (c->seen_next + 1) % RNS_SEEN_MAX;
    if (c->seen_count < RNS_SEEN_MAX)
        c->seen_count++;
    return 0;
}

/* ---- client ---- */

static void
set_state(struct rns_client *c, enum rns_state state, const char *reason)
{
    c->state = state;
    if (c->cb.state)
        c->cb.state(c->ctx, state, reason);
}

static void
wipe_link(struct rns_client *c)
{
    cr_wipe(c->eph_x_prv, sizeof(c->eph_x_prv));
    cr_wipe(c->eph_ed_seed, sizeof(c->eph_ed_seed));
    cr_wipe(c->key, sizeof(c->key));
}

void
rns_client_init(struct rns_client *c, const struct rns_identity *id,
                const uint8_t dest_hash[RNS_HASH_LEN], int shared_instance,
                const struct rns_callbacks *cb, void *ctx)
{
    memset(c, 0, sizeof(*c));
    c->id = *id;
    c->cb = *cb;
    c->ctx = ctx;
    memcpy(c->dest_hash, dest_hash, RNS_HASH_LEN);
    c->shared_instance = shared_instance;
    c->path_timeout = PATH_TIMEOUT_DEFAULT;
    c->mdu = RNS_LINK_MDU;
    c->state = RNS_IDLE;
}

void
rns_client_wipe(struct rns_client *c)
{
    wipe_link(c);
    cr_wipe(&c->id, sizeof(c->id));
}

static void
send_path_request(struct rns_client *c, double now)
{
    uint8_t pr_dest[RNS_HASH_LEN], data[2 * RNS_HASH_LEN], pkt[RNS_MTU];
    size_t n;

    rns_destination_hash(PATH_REQUEST_NAME, NULL, pr_dest);
    memcpy(data, c->dest_hash, RNS_HASH_LEN);
    cr_random(data + RNS_HASH_LEN, RNS_HASH_LEN);   /* request tag */
    n = build_packet(pkt,
                     make_flags(HEADER_1, 0, TRANSPORT_BROADCAST, RNS_DT_PLAIN, RNS_PT_DATA),
                     0, NULL, pr_dest, RNS_CTX_NONE, data, sizeof(data));
    c->path_requested = now;
    clog_(c, RNS_LOG_DEBUG, "path request sent");
    transmit(c, pkt, n, now);
}

static size_t
link_mdu_for(int mtu)
{
    return (size_t)((mtu - 1 - RNS_HEADER_MINSIZE - CR_TOKEN_OVERHEAD) / 16) * 16 - 1;
}

static void
send_link_request(struct rns_client *c, double now)
{
    uint8_t data[64 + SIGNALLING_LEN], pkt[RNS_MTU], hashable[RNS_MTU];
    uint32_t signalling;
    size_t n, hn;
    uint8_t flags;
    int via_transport;

    if (cr_random(c->eph_x_prv, 32) != 0 || cr_random(c->eph_ed_seed, 32) != 0
        || cr_x25519_public(c->eph_x_prv, c->eph_x_pub) != 0
        || cr_ed25519_public(c->eph_ed_seed, c->eph_ed_pub) != 0) {
        rns_client_close(c, now, "could not generate link keys");
        return;
    }

    memcpy(data, c->eph_x_pub, 32);
    memcpy(data + 32, c->eph_ed_pub, 32);
    signalling = (RNS_MTU & 0x1fffff) | ((uint32_t)((MODE_AES256_CBC << 5) & 0xe0) << 16);
    data[64] = (uint8_t)(signalling >> 16);
    data[65] = (uint8_t)(signalling >> 8);
    data[66] = (uint8_t)signalling;

    flags = make_flags(HEADER_1, 0, TRANSPORT_BROADCAST, RNS_DT_SINGLE, RNS_PT_LINKREQUEST);

    /* link id: hash of the HEADER_1 hashable part without the signalling bytes */
    hashable[0] = flags & 0x0f;
    memcpy(hashable + 1, c->dest_hash, RNS_HASH_LEN);
    hashable[1 + RNS_HASH_LEN] = RNS_CTX_NONE;
    memcpy(hashable + 2 + RNS_HASH_LEN, data, 64);
    hn = 2 + RNS_HASH_LEN + 64;
    truncated_hash(hashable, hn, c->link_id);

    /* As Transport.outbound(): more than one hop away, or one hop away
     * behind a shared instance, the request goes in transport. */
    via_transport = c->hops > 1 || (c->hops == 1 && c->shared_instance);
    if (via_transport)
        n = build_packet(pkt,
                         make_flags(HEADER_2, 0, TRANSPORT_TRANSPORT, RNS_DT_SINGLE,
                                    RNS_PT_LINKREQUEST),
                         0, c->next_hop, c->dest_hash, RNS_CTX_NONE, data, sizeof(data));
    else
        n = build_packet(pkt, flags, 0, NULL, c->dest_hash, RNS_CTX_NONE, data, sizeof(data));

    c->request_time = now;
    c->establishment_timeout = PER_HOP_TIMEOUT * (c->hops > 1 ? c->hops : 1) + 15.0;
    set_state(c, RNS_LINKING, NULL);
    {
        char hex[2 * RNS_HASH_LEN + 1];
        rns_hex(c->link_id, RNS_HASH_LEN, hex);
        clog_(c, RNS_LOG_DEBUG, "link request %s sent, %d hop%s away%s", hex, c->hops,
              c->hops == 1 ? "" : "s", via_transport ? ", in transport" : "");
    }
    transmit(c, pkt, n, now);
}

void
rns_client_start(struct rns_client *c, double now)
{
    c->path_started = now;
    c->have_path = 0;
    c->last_inbound = c->last_outbound = c->last_keepalive = now;
    set_state(c, RNS_PATH, NULL);
    send_path_request(c, now);
}

static void
handle_announce(struct rns_client *c, const struct rns_packet *p, double now)
{
    uint8_t signed_data[RNS_HASH_LEN + RNS_MTU];
    uint8_t identity_hash[RNS_HASH_LEN], expected[RNS_HASH_LEN];
    uint8_t material[RNS_NAME_HASH_LEN + RNS_HASH_LEN];
    uint8_t want_name[RNS_NAME_HASH_LEN];
    const uint8_t *pub, *name_hash, *random_hash, *ratchet = NULL, *sig, *app_data;
    size_t ratchet_len = p->context_flag ? 32 : 0, min_len, app_len, n = 0;

    if (memcmp(p->dest, c->dest_hash, RNS_HASH_LEN) != 0)
        return;
    min_len = RNS_PUBKEY_LEN + RNS_NAME_HASH_LEN + 10 + ratchet_len + 64;
    if (p->data_len < min_len)
        return;
    pub = p->data;
    name_hash = pub + RNS_PUBKEY_LEN;
    random_hash = name_hash + RNS_NAME_HASH_LEN;
    if (ratchet_len)
        ratchet = random_hash + 10;
    sig = random_hash + 10 + ratchet_len;
    app_data = sig + 64;
    app_len = p->data_len - min_len;

    memcpy(signed_data + n, p->dest, RNS_HASH_LEN); n += RNS_HASH_LEN;
    memcpy(signed_data + n, pub, RNS_PUBKEY_LEN); n += RNS_PUBKEY_LEN;
    memcpy(signed_data + n, name_hash, RNS_NAME_HASH_LEN); n += RNS_NAME_HASH_LEN;
    memcpy(signed_data + n, random_hash, 10); n += 10;
    if (ratchet_len) {
        memcpy(signed_data + n, ratchet, ratchet_len);
        n += ratchet_len;
    }
    memcpy(signed_data + n, app_data, app_len); n += app_len;

    if (!cr_ed25519_verify(pub + 32, signed_data, n, sig)) {
        clog_(c, RNS_LOG_DEBUG, "announce with an invalid signature ignored");
        return;
    }
    truncated_hash(pub, RNS_PUBKEY_LEN, identity_hash);
    memcpy(material, name_hash, RNS_NAME_HASH_LEN);
    memcpy(material + RNS_NAME_HASH_LEN, identity_hash, RNS_HASH_LEN);
    truncated_hash(material, sizeof(material), expected);
    if (memcmp(expected, c->dest_hash, RNS_HASH_LEN) != 0) {
        clog_(c, RNS_LOG_DEBUG, "announce whose hash does not match its key ignored");
        return;
    }
    rns_name_hash(HUB_NAME, want_name);
    if (memcmp(name_hash, want_name, RNS_NAME_HASH_LEN) != 0) {
        rns_client_close(c, now, "that destination is not an RRC hub (rrc.hub)");
        return;
    }
    if (c->have_path && memcmp(c->dest_pub, pub, RNS_PUBKEY_LEN) != 0) {
        clog_(c, RNS_LOG_ERROR, "announce with a different key for the same hub ignored");
        return;
    }

    memcpy(c->dest_pub, pub, RNS_PUBKEY_LEN);
    /* As Transport: the next hop is the transport node that forwarded it,
     * or the destination itself when it reached us directly. */
    memcpy(c->next_hop, p->transport_id ? p->transport_id : p->dest, RNS_HASH_LEN);
    c->hops = p->hops;
    if (!c->have_path)
        clog_(c, RNS_LOG_DEBUG, "path found: %d hop%s", c->hops, c->hops == 1 ? "" : "s");
    c->have_path = 1;

    if (c->state == RNS_PATH)
        send_link_request(c, now);
}

static void
update_keepalive(struct rns_client *c)
{
    double k = c->rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT);

    if (k > KEEPALIVE_MAX)
        k = KEEPALIVE_MAX;
    if (k < KEEPALIVE_MIN)
        k = KEEPALIVE_MIN;
    c->keepalive = k;
    c->stale_time = k * STALE_FACTOR;
}

static int
send_link_packet(struct rns_client *c, uint8_t context, const uint8_t *plain, size_t len,
                 int encrypt, double now)
{
    uint8_t token[RNS_MTU], pkt[RNS_MTU];
    long tlen;
    size_t n;

    if (encrypt) {
        if (len > c->mdu)
            return -1;
        tlen = cr_token_encrypt(c->key, NULL, plain, len, token);
        if (tlen < 0)
            return -1;
    } else {
        if (len > sizeof(token))
            return -1;
        memcpy(token, plain, len);
        tlen = (long)len;
    }
    n = build_packet(pkt, make_flags(HEADER_1, 0, TRANSPORT_BROADCAST, RNS_DT_LINK, RNS_PT_DATA),
                     0, NULL, c->link_id, context, token, (size_t)tlen);
    return transmit(c, pkt, n, now);
}

static void
handle_link_proof(struct rns_client *c, const struct rns_packet *p, double now)
{
    uint8_t signed_data[RNS_HASH_LEN + 32 + 32 + SIGNALLING_LEN];
    uint8_t shared[32], rtt_msg[9];
    const uint8_t *sig, *peer_pub, *signalling = NULL;
    size_t n = 0;
    int mtu = RNS_MTU;
    uint64_t bits;
    int i;

    if (c->state != RNS_LINKING)
        return;
    if (p->data_len == 64 + 32 + SIGNALLING_LEN) {
        signalling = p->data + 96;
        if (((signalling[0] & 0xe0) >> 5) != MODE_AES256_CBC) {
            rns_client_close(c, now, "hub proposed an unsupported link mode");
            return;
        }
        mtu = ((signalling[0] << 16) | (signalling[1] << 8) | signalling[2]) & 0x1fffff;
        if (mtu > RNS_MTU || mtu < 200)
            mtu = RNS_MTU;
    } else if (p->data_len != 64 + 32) {
        return;
    }
    sig = p->data;
    peer_pub = p->data + 64;

    memcpy(signed_data + n, c->link_id, RNS_HASH_LEN); n += RNS_HASH_LEN;
    memcpy(signed_data + n, peer_pub, 32); n += 32;
    memcpy(signed_data + n, c->dest_pub + 32, 32); n += 32;
    if (signalling) {
        memcpy(signed_data + n, signalling, SIGNALLING_LEN);
        n += SIGNALLING_LEN;
    }
    if (!cr_ed25519_verify(c->dest_pub + 32, signed_data, n, sig)) {
        clog_(c, RNS_LOG_DEBUG, "link proof with an invalid signature ignored");
        return;
    }
    if (cr_x25519_shared(c->eph_x_prv, peer_pub, shared) != 0) {
        rns_client_close(c, now, "key exchange failed");
        return;
    }
    cr_hkdf(shared, sizeof(shared), c->link_id, RNS_HASH_LEN, NULL, 0, c->key, sizeof(c->key));
    cr_wipe(shared, sizeof(shared));
    cr_wipe(c->eph_x_prv, sizeof(c->eph_x_prv));

    c->rtt = now - c->request_time;
    if (c->rtt <= 0)
        c->rtt = 0.001;
    c->mdu = link_mdu_for(mtu);
    c->activated_at = now;
    c->last_inbound = now;
    update_keepalive(c);

    /* RTT, msgpack float64 */
    memcpy(&bits, &c->rtt, sizeof(bits));
    rtt_msg[0] = 0xcb;
    for (i = 0; i < 8; i++)
        rtt_msg[1 + i] = (uint8_t)(bits >> (56 - 8 * i));
    c->state = RNS_ACTIVE;
    send_link_packet(c, RNS_CTX_LRRTT, rtt_msg, sizeof(rtt_msg), 1, now);
    c->last_keepalive = now;
    clog_(c, RNS_LOG_DEBUG, "link established, rtt %.0f ms, mdu %zu", c->rtt * 1000.0, c->mdu);
    set_state(c, RNS_ACTIVE, NULL);
}

static void
handle_link_data(struct rns_client *c, const struct rns_packet *p, double now)
{
    uint8_t plain[RNS_MTU];
    long n;

    c->last_inbound = now;
    switch (p->context) {
    case RNS_CTX_NONE:
        n = cr_token_decrypt(c->key, p->data, p->data_len, plain);
        if (n < 0) {
            clog_(c, RNS_LOG_DEBUG, "undecryptable link packet dropped");
            return;
        }
        if (c->cb.data)
            c->cb.data(c->ctx, plain, (size_t)n);
        return;
    case RNS_CTX_KEEPALIVE:
        return;
    case RNS_CTX_LINKCLOSE:
        n = cr_token_decrypt(c->key, p->data, p->data_len, plain);
        if (n == RNS_HASH_LEN && memcmp(plain, c->link_id, RNS_HASH_LEN) == 0) {
            wipe_link(c);
            set_state(c, RNS_CLOSED, "the hub closed the link");
        }
        return;
    case RNS_CTX_RESOURCE_ADV:
        clog_(c, RNS_LOG_DEBUG, "resource transfer offered by the hub, not supported");
        return;
    default:
        clog_(c, RNS_LOG_DEBUG, "link packet with context 0x%02x ignored", p->context);
        return;
    }
}

void
rns_client_inbound(struct rns_client *c, const uint8_t *raw, size_t len, double now)
{
    struct rns_packet p;

    if (rns_packet_parse(raw, len, &p) != 0)
        return;
    c->rx_packets++;
    if (seen_before(c, &p))
        return;
    p.hops++;   /* as Transport.inbound(): count the hop to us */

    if (p.packet_type == RNS_PT_ANNOUNCE) {
        if (c->state != RNS_CLOSED)
            handle_announce(c, &p, now);
        return;
    }
    if (c->state != RNS_LINKING && c->state != RNS_ACTIVE)
        return;
    if (memcmp(p.dest, c->link_id, RNS_HASH_LEN) != 0)
        return;
    if (p.packet_type == RNS_PT_PROOF && p.context == RNS_CTX_LRPROOF) {
        handle_link_proof(c, &p, now);
        return;
    }
    if (c->state != RNS_ACTIVE)
        return;
    if (p.packet_type == RNS_PT_DATA)
        handle_link_data(c, &p, now);
    else if (p.packet_type == RNS_PT_PROOF)
        c->last_inbound = now;   /* delivery proof for one of our packets */
}

int
rns_client_send(struct rns_client *c, const uint8_t *data, size_t len, double now)
{
    if (c->state != RNS_ACTIVE || len == 0 || len > c->mdu)
        return -1;
    return send_link_packet(c, RNS_CTX_NONE, data, len, 1, now);
}

int
rns_client_identify(struct rns_client *c, double now)
{
    uint8_t msg[RNS_HASH_LEN + RNS_PUBKEY_LEN], proof[RNS_PUBKEY_LEN + 64];

    if (c->state != RNS_ACTIVE)
        return -1;
    memcpy(msg, c->link_id, RNS_HASH_LEN);
    memcpy(msg + RNS_HASH_LEN, c->id.pub, RNS_PUBKEY_LEN);
    memcpy(proof, c->id.pub, RNS_PUBKEY_LEN);
    if (cr_ed25519_sign(c->id.ed_seed, msg, sizeof(msg), proof + RNS_PUBKEY_LEN) != 0)
        return -1;
    return send_link_packet(c, RNS_CTX_LINKIDENTIFY, proof, sizeof(proof), 1, now);
}

void
rns_client_close(struct rns_client *c, double now, const char *reason)
{
    if (c->state == RNS_CLOSED)
        return;
    if (c->state == RNS_ACTIVE)
        send_link_packet(c, RNS_CTX_LINKCLOSE, c->link_id, RNS_HASH_LEN, 1, now);
    wipe_link(c);
    set_state(c, RNS_CLOSED, reason);
}

void
rns_client_tick(struct rns_client *c, double now)
{
    double last_in;
    uint8_t ka = 0xff;

    switch (c->state) {
    case RNS_PATH:
        if (now - c->path_started >= c->path_timeout) {
            char msg[96];
            snprintf(msg, sizeof(msg), "no path to the hub after %.0f seconds", c->path_timeout);
            rns_client_close(c, now, msg);
        } else if (now - c->path_requested >= PATH_REQUEST_INTERVAL) {
            send_path_request(c, now);
        }
        break;
    case RNS_LINKING:
        if (now >= c->request_time + c->establishment_timeout)
            rns_client_close(c, now, "the hub did not answer the link request");
        break;
    case RNS_ACTIVE:
        last_in = c->last_inbound > c->activated_at ? c->last_inbound : c->activated_at;
        if (now >= last_in + c->stale_time + c->rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE) {
            rns_client_close(c, now, "the link timed out");
            break;
        }
        if ((now >= last_in + c->keepalive || now >= c->last_outbound + c->keepalive)
            && now >= c->last_keepalive + c->keepalive) {
            send_link_packet(c, RNS_CTX_KEEPALIVE, &ka, 1, 0, now);
            c->last_keepalive = now;
        }
        break;
    default:
        break;
    }
}
