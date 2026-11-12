/*
 * resource.c - receiving Reticulum resources on the link
 *
 * Follows the receiving side of RNS 1.x Resource.py: accept(),
 * hashmap_update(), request_next(), receive_part(), assemble(), prove()
 * and cancel(). The advertisement and hashmap updates are msgpack, read
 * here with a small bounded reader.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <bzlib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "resource.h"

#define HASHMAP_NOT_EXHAUSTED 0x00
#define HASHMAP_EMPTY 0xfe
#define HASHMAP_EXHAUSTED 0xff

#define WINDOW 4
#define WINDOW_MIN 2
#define WINDOW_MAX 10        /* WINDOW_MAX_SLOW: we never ask for more */
#define WINDOW_FLEXIBILITY 4
#define MAX_RETRIES 16
#define PART_TIMEOUT_FACTOR 4.0
#define RETRY_GRACE 0.25
#define PER_RETRY_DELAY 0.5
#define TIMEOUT_GRACE 1.0

/* header (35) + IFAC (1): a part fills the rest of a packet */
#define PART_OVERHEAD 36
/* the stream is the data plus the random prefix, padding and token */
#define TRANSFER_MAX (RNS_RESOURCE_MAX + 128)

#define P_MAPPED 0x01
#define P_RECEIVED 0x02

struct rns_resource {
    uint8_t hash[RNS_RES_HASH_LEN];
    uint8_t random[RNS_RES_RANDOM_LEN];
    uint64_t flags;
    size_t size;            /* transfer size */
    size_t sdu;
    size_t total_parts;
    uint8_t *stream;        /* size bytes, part i at i * sdu */
    uint8_t *hashmap;       /* total_parts map hashes */
    uint8_t *part;          /* total_parts P_* flags */
    size_t hashmap_height;
    size_t received;
    size_t outstanding;
    size_t window, window_max, window_min;
    long consecutive;       /* highest index up to which every part is in */
    int waiting_for_hmu;
    int retries_left;
    double last_activity;
};

static void
rlog(struct rns_client *c, int level, const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    if (!c->cb.log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    c->cb.log(c->ctx, level, buf);
}

/* ---- msgpack, the subset umsgpack writes ---- */

enum mp_type { MP_UINT, MP_NINT, MP_NIL, MP_BOOL, MP_BIN, MP_STR, MP_ARRAY, MP_MAP, MP_OTHER };

struct mp {
    const uint8_t *p;
    size_t len, off;
};

struct mp_item {
    enum mp_type type;
    uint64_t u;             /* UINT, BOOL */
    const uint8_t *p;       /* BIN, STR */
    size_t len;             /* BIN, STR: bytes; ARRAY, MAP: entries */
};

#define MP_MAX_DEPTH 8

static int
mp_take(struct mp *m, size_t n, const uint8_t **out)
{
    if (m->len - m->off < n)
        return -1;
    *out = m->p + m->off;
    m->off += n;
    return 0;
}

static int
mp_be(struct mp *m, size_t n, uint64_t *v)
{
    const uint8_t *b;
    size_t i;

    if (mp_take(m, n, &b) != 0)
        return -1;
    *v = 0;
    for (i = 0; i < n; i++)
        *v = (*v << 8) | b[i];
    return 0;
}

static int
mp_read(struct mp *m, struct mp_item *it)
{
    const uint8_t *b;
    uint64_t n;
    uint8_t c;

    memset(it, 0, sizeof(*it));
    if (mp_take(m, 1, &b) != 0)
        return -1;
    c = *b;
    if (c <= 0x7f) {
        it->type = MP_UINT;
        it->u = c;
        return 0;
    }
    if (c >= 0xe0) {
        it->type = MP_NINT;
        return 0;
    }
    if ((c & 0xf0) == 0x80 || (c & 0xf0) == 0x90) {
        it->type = (c & 0xf0) == 0x80 ? MP_MAP : MP_ARRAY;
        n = c & 0x0f;
        goto container;
    }
    if ((c & 0xe0) == 0xa0) {
        it->type = MP_STR;
        n = c & 0x1f;
        goto bytes;
    }
    switch (c) {
    case 0xc0:
        it->type = MP_NIL;
        return 0;
    case 0xc2:
    case 0xc3:
        it->type = MP_BOOL;
        it->u = c & 1;
        return 0;
    case 0xc4: case 0xc5: case 0xc6:
        it->type = MP_BIN;
        if (mp_be(m, (size_t)1 << (c - 0xc4), &n) != 0)
            return -1;
        goto bytes;
    case 0xd9: case 0xda: case 0xdb:
        it->type = MP_STR;
        if (mp_be(m, (size_t)1 << (c - 0xd9), &n) != 0)
            return -1;
        goto bytes;
    case 0xcc: case 0xcd: case 0xce: case 0xcf:
        it->type = MP_UINT;
        return mp_be(m, (size_t)1 << (c - 0xcc), &it->u);
    case 0xd0: case 0xd1: case 0xd2: case 0xd3: {
        size_t w = (size_t)1 << (c - 0xd0);
        if (mp_be(m, w, &n) != 0)
            return -1;
        if (n >> (8 * w - 1)) {
            it->type = MP_NINT;
        } else {
            it->type = MP_UINT;
            it->u = n;
        }
        return 0;
    }
    case 0xca:
    case 0xcb:
        it->type = MP_OTHER;
        return mp_take(m, c == 0xca ? 4 : 8, &b);
    case 0xd4: case 0xd5: case 0xd6: case 0xd7: case 0xd8:
        it->type = MP_OTHER;
        return mp_take(m, 1 + ((size_t)1 << (c - 0xd4)), &b);
    case 0xc7: case 0xc8: case 0xc9:
        it->type = MP_OTHER;
        if (mp_be(m, (size_t)1 << (c - 0xc7), &n) != 0 || n > m->len)
            return -1;
        return mp_take(m, 1 + (size_t)n, &b);
    case 0xdc: case 0xdd:
        it->type = MP_ARRAY;
        if (mp_be(m, c == 0xdc ? 2 : 4, &n) != 0)
            return -1;
        goto container;
    case 0xde: case 0xdf:
        it->type = MP_MAP;
        if (mp_be(m, c == 0xde ? 2 : 4, &n) != 0)
            return -1;
        goto container;
    default:
        return -1;
    }

bytes:
    if (n > m->len - m->off)
        return -1;
    it->len = (size_t)n;
    return mp_take(m, it->len, &it->p);

container:
    /* every entry takes at least a byte */
    if (n > m->len - m->off)
        return -1;
    it->len = (size_t)n;
    return 0;
}

/* Skip what follows an item already read: a container's entries. */
static int
mp_skip_rest(struct mp *m, const struct mp_item *it, int depth)
{
    struct mp_item sub;
    size_t i, n;

    if (it->type != MP_ARRAY && it->type != MP_MAP)
        return 0;
    if (depth >= MP_MAX_DEPTH)
        return -1;
    n = it->type == MP_MAP ? 2 * it->len : it->len;
    for (i = 0; i < n; i++)
        if (mp_read(m, &sub) != 0 || mp_skip_rest(m, &sub, depth + 1) != 0)
            return -1;
    return 0;
}

int
rns_adv_unpack(const uint8_t *buf, size_t len, struct rns_adv *adv)
{
    struct mp m = { buf, len, 0 };
    struct mp_item map, key, v;
    unsigned seen = 0, bit;
    size_t k;

    memset(adv, 0, sizeof(*adv));
    if (mp_read(&m, &map) != 0 || map.type != MP_MAP)
        return -1;
    for (k = 0; k < map.len; k++) {
        if (mp_read(&m, &key) != 0 || mp_skip_rest(&m, &key, 1) != 0
            || mp_read(&m, &v) != 0)
            return -1;
        if (key.type != MP_STR || key.len != 1) {
            if (mp_skip_rest(&m, &v, 1) != 0)
                return -1;
            continue;
        }
        switch (key.p[0]) {
        case 't': case 'd': case 'n': case 'i': case 'l': case 'f': {
            static const char order[] = "tdnilf";
            uint64_t *dst[] = { &adv->t, &adv->d, &adv->n, &adv->i, &adv->l, &adv->f };
            if (v.type != MP_UINT)
                return -1;
            bit = (unsigned)(strchr(order, key.p[0]) - order);
            *dst[bit] = v.u;
            seen |= 1u << bit;
            break;
        }
        case 'h':
        case 'o':
            if (v.type != MP_BIN || v.len != RNS_RES_HASH_LEN)
                return -1;
            memcpy(key.p[0] == 'h' ? adv->h : adv->o, v.p, RNS_RES_HASH_LEN);
            seen |= key.p[0] == 'h' ? 1u << 6 : 1u << 7;
            break;
        case 'r':
            if (v.type != MP_BIN || v.len != RNS_RES_RANDOM_LEN)
                return -1;
            memcpy(adv->r, v.p, RNS_RES_RANDOM_LEN);
            seen |= 1u << 8;
            break;
        case 'm':
            if (v.type != MP_BIN)
                return -1;
            adv->m = v.p;
            adv->m_len = v.len;
            seen |= 1u << 9;
            break;
        case 'q':
            if (v.type != MP_NIL && v.type != MP_BIN)
                return -1;
            adv->has_q = v.type == MP_BIN;
            seen |= 1u << 10;
            break;
        default:
            if (mp_skip_rest(&m, &v, 1) != 0)
                return -1;
            break;
        }
    }
    /* ResourceAdvertisement.unpack() reads every one of the eleven keys */
    return seen == 0x7ff ? 0 : -1;
}

int
rns_hmu_unpack(const uint8_t *buf, size_t len, uint64_t *segment,
               const uint8_t **map, size_t *map_len)
{
    struct mp m = { buf, len, 0 };
    struct mp_item arr, seg, hm;

    if (mp_read(&m, &arr) != 0 || arr.type != MP_ARRAY || arr.len < 2
        || mp_read(&m, &seg) != 0 || seg.type != MP_UINT
        || mp_read(&m, &hm) != 0 || hm.type != MP_BIN)
        return -1;
    *segment = seg.u;
    *map = hm.p;
    *map_len = hm.len;
    return 0;
}

/* ---- assembly ---- */

static int
bz2_decompress(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len)
{
    bz_stream z;
    uint8_t *buf;
    size_t cap = RNS_RESOURCE_MAX + 1;
    int rc;

    if (len > UINT_MAX)
        return -1;
    buf = malloc(cap);
    if (!buf)
        return -1;
    memset(&z, 0, sizeof(z));
    if (BZ2_bzDecompressInit(&z, 0, 0) != BZ_OK) {
        free(buf);
        return -1;
    }
    z.next_in = (char *)in;
    z.avail_in = (unsigned)len;
    z.next_out = (char *)buf;
    z.avail_out = (unsigned)cap;
    for (;;) {
        rc = BZ2_bzDecompress(&z);
        if (rc == BZ_STREAM_END)
            break;
        /* an error, more than we take, or a stream cut short */
        if (rc != BZ_OK || z.avail_out == 0 || z.avail_in == 0) {
            BZ2_bzDecompressEnd(&z);
            free(buf);
            return -1;
        }
    }
    BZ2_bzDecompressEnd(&z);
    *out_len = cap - z.avail_out;
    if (*out_len > RNS_RESOURCE_MAX) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

int
rns_resource_decode(const uint8_t key[64], uint64_t flags,
                    const uint8_t *stream, size_t len,
                    const uint8_t random_hash[RNS_RES_RANDOM_LEN],
                    const uint8_t hash[RNS_RES_HASH_LEN],
                    uint8_t **out, size_t *out_len)
{
    uint8_t *plain = NULL, *data = NULL, check[CR_SHA256_LEN];
    const uint8_t *body = stream;
    size_t body_len = len, plain_cap = len, n = 0;
    long pl;

    *out = NULL;
    *out_len = 0;
    if (len > TRANSFER_MAX)
        return -1;
    if (flags & RNS_RES_F_ENCRYPTED) {
        plain = malloc(plain_cap ? plain_cap : 1);
        if (!plain)
            return -1;
        pl = cr_token_decrypt(key, stream, len, plain);
        if (pl < 0)
            goto fail;
        body = plain;
        body_len = (size_t)pl;
    }
    if (body_len < RNS_RES_RANDOM_LEN)
        goto fail;
    body += RNS_RES_RANDOM_LEN;
    body_len -= RNS_RES_RANDOM_LEN;
    if (flags & RNS_RES_F_COMPRESSED) {
        if (bz2_decompress(body, body_len, &data, &n) != 0)
            goto fail;
    } else {
        if (body_len > RNS_RESOURCE_MAX)
            goto fail;
        data = malloc(body_len ? body_len : 1);
        if (!data)
            goto fail;
        memcpy(data, body, body_len);
        n = body_len;
    }
    cr_sha256_2(data, n, random_hash, RNS_RES_RANDOM_LEN, check);
    if (memcmp(check, hash, RNS_RES_HASH_LEN) != 0)
        goto fail;
    if (plain) {
        cr_wipe(plain, plain_cap);
        free(plain);
    }
    *out = data;
    *out_len = n;
    return 0;

fail:
    if (plain) {
        cr_wipe(plain, plain_cap);
        free(plain);
    }
    free(data);
    return -1;
}

/* ---- the transfer ---- */

void
rns_resource_free(struct rns_client *c)
{
    struct rns_resource *r = c->resource;

    if (!r)
        return;
    free(r->stream);
    free(r->hashmap);
    free(r->part);
    free(r);
    c->resource = NULL;
}

/* Tell the hub we don't want this resource (RESOURCE_RCL), as
 * Resource.reject() and the receiving side of Resource.cancel(). */
static void
send_cancel(struct rns_client *c, const uint8_t hash[RNS_RES_HASH_LEN], double now)
{
    if (c->state == RNS_ACTIVE)
        rns_link_packet(c, RNS_PT_DATA, RNS_CTX_RESOURCE_RCL, hash, RNS_RES_HASH_LEN, 1, now);
}

static void
cancel(struct rns_client *c, double now, const char *why)
{
    struct rns_resource *r = c->resource;

    if (!r)
        return;
    rlog(c, RNS_LOG_INFO, "resource transfer from the hub cancelled: %s", why);
    send_cancel(c, r->hash, now);
    rns_resource_free(c);
}

static size_t
part_len(const struct rns_resource *r, size_t i)
{
    return i + 1 < r->total_parts ? r->sdu : r->size - (r->total_parts - 1) * r->sdu;
}

/* Ask for the next window of parts, or for more of the hashmap:
 * [flag][last map hash, when exhausted][resource hash][map hashes]. */
static void
request_next(struct rns_client *c, double now)
{
    struct rns_resource *r = c->resource;
    uint8_t req[1 + RNS_RES_MAPHASH_LEN + RNS_RES_HASH_LEN + WINDOW_MAX * RNS_RES_MAPHASH_LEN];
    uint8_t wanted[WINDOW_MAX * RNS_RES_MAPHASH_LEN];
    uint8_t flag = HASHMAP_NOT_EXHAUSTED;
    size_t n = 0, hashes = 0, pn, end;

    if (r->waiting_for_hmu)
        return;
    r->outstanding = 0;
    if (!(r->part[0] & P_MAPPED)) {
        /* the advertisement carried no hashmap (RNS 1.6) */
        flag = HASHMAP_EMPTY;
    } else {
        pn = (size_t)(r->consecutive + 1);
        end = pn + r->window < r->total_parts ? pn + r->window : r->total_parts;
        for (; pn < end; pn++) {
            if (!(r->part[pn] & P_RECEIVED)) {
                if (r->part[pn] & P_MAPPED) {
                    memcpy(wanted + hashes * RNS_RES_MAPHASH_LEN,
                           r->hashmap + pn * RNS_RES_MAPHASH_LEN, RNS_RES_MAPHASH_LEN);
                    hashes++;
                } else {
                    flag = HASHMAP_EXHAUSTED;
                }
            }
            if (hashes >= r->window || flag == HASHMAP_EXHAUSTED)
                break;
        }
    }
    r->outstanding = hashes;
    req[n++] = flag;
    if (flag == HASHMAP_EXHAUSTED) {
        /* the last map hash we have, so the hub knows which segment is next */
        memcpy(req + n, r->hashmap + (r->hashmap_height - 1) * RNS_RES_MAPHASH_LEN,
               RNS_RES_MAPHASH_LEN);
        n += RNS_RES_MAPHASH_LEN;
    }
    if (flag != HASHMAP_NOT_EXHAUSTED)
        r->waiting_for_hmu = 1;
    memcpy(req + n, r->hash, RNS_RES_HASH_LEN);
    n += RNS_RES_HASH_LEN;
    memcpy(req + n, wanted, hashes * RNS_RES_MAPHASH_LEN);
    n += hashes * RNS_RES_MAPHASH_LEN;
    r->last_activity = now;
    rns_link_packet(c, RNS_PT_DATA, RNS_CTX_RESOURCE_REQ, req, n, 1, now);
}

/* Returns -1 for an update that doesn't fit the resource. */
static int
hashmap_update(struct rns_client *c, uint64_t segment, const uint8_t *map, size_t len,
               double now)
{
    struct rns_resource *r = c->resource;
    size_t hashes = len / RNS_RES_MAPHASH_LEN, i, idx;

    if (len % RNS_RES_MAPHASH_LEN || segment > r->total_parts / RNS_RES_HASHMAP_MAX_LEN
        || segment * RNS_RES_HASHMAP_MAX_LEN + hashes > r->total_parts
        || (hashes < 1 && segment != 0))
        return -1;
    for (i = 0; i < hashes; i++) {
        idx = (size_t)segment * RNS_RES_HASHMAP_MAX_LEN + i;
        if (!(r->part[idx] & P_MAPPED)) {
            r->part[idx] |= P_MAPPED;
            r->hashmap_height++;
        }
        memcpy(r->hashmap + idx * RNS_RES_MAPHASH_LEN, map + i * RNS_RES_MAPHASH_LEN,
               RNS_RES_MAPHASH_LEN);
    }
    r->waiting_for_hmu = 0;
    request_next(c, now);
    return 0;
}

static const char *
refusal(const struct rns_client *c, const struct rns_adv *adv)
{
    size_t sdu;

    if (adv->f & (RNS_RES_F_REQUEST | RNS_RES_F_RESPONSE))
        return "a request or response we did not make";
    if ((adv->f & RNS_RES_F_SPLIT) || adv->l != 1 || adv->i != 1)
        return "split into segments";
    if (adv->d > RNS_RESOURCE_MAX || adv->t > TRANSFER_MAX)
        return "too large";
    if (adv->t == 0)
        return "empty";
    if (c->mtu <= PART_OVERHEAD)
        return "link MTU too small";
    sdu = (size_t)c->mtu - PART_OVERHEAD;
    if (adv->n != (adv->t + sdu - 1) / sdu)
        return "part count does not match its size";
    if (adv->m_len % RNS_RES_MAPHASH_LEN || adv->m_len / RNS_RES_MAPHASH_LEN > adv->n)
        return "malformed hashmap";
    return NULL;
}

void
rns_resource_advertised(struct rns_client *c, const uint8_t *plain, size_t len, double now)
{
    struct rns_adv adv;
    struct rns_resource *r;
    const char *why;

    if (rns_adv_unpack(plain, len, &adv) != 0) {
        rlog(c, RNS_LOG_DEBUG, "malformed resource advertisement ignored");
        return;
    }
    if (c->resource && memcmp(c->resource->hash, adv.h, RNS_RES_HASH_LEN) == 0)
        return;   /* advertised again while we transfer it */
    why = refusal(c, &adv);
    if (why) {
        rlog(c, RNS_LOG_INFO, "resource of %llu bytes from the hub refused: %s",
             (unsigned long long)adv.d, why);
        send_cancel(c, adv.h, now);
        return;
    }
    if (c->resource)
        cancel(c, now, "the hub started another");

    r = calloc(1, sizeof(*r));
    if (r) {
        r->stream = malloc((size_t)adv.t);
        r->hashmap = calloc((size_t)adv.n, RNS_RES_MAPHASH_LEN);
        r->part = calloc((size_t)adv.n, 1);
    }
    if (!r || !r->stream || !r->hashmap || !r->part) {
        if (r) {
            free(r->stream);
            free(r->hashmap);
            free(r->part);
            free(r);
        }
        rlog(c, RNS_LOG_ERROR, "out of memory for a resource from the hub");
        send_cancel(c, adv.h, now);
        return;
    }
    memcpy(r->hash, adv.h, RNS_RES_HASH_LEN);
    memcpy(r->random, adv.r, RNS_RES_RANDOM_LEN);
    r->flags = adv.f;
    r->size = (size_t)adv.t;
    r->sdu = (size_t)c->mtu - PART_OVERHEAD;
    r->total_parts = (size_t)adv.n;
    r->consecutive = -1;
    r->window = WINDOW;
    r->window_max = WINDOW_MAX;
    r->window_min = WINDOW_MIN;
    r->retries_left = MAX_RETRIES;
    r->last_activity = now;
    c->resource = r;
    rlog(c, RNS_LOG_DEBUG, "receiving a resource of %llu bytes in %zu part%s",
         (unsigned long long)adv.d, r->total_parts, r->total_parts == 1 ? "" : "s");
    if (hashmap_update(c, 0, adv.m, adv.m_len, now) != 0)
        cancel(c, now, "invalid hashmap");
}

void
rns_resource_hmu(struct rns_client *c, const uint8_t *plain, size_t len, double now)
{
    struct rns_resource *r = c->resource;
    const uint8_t *map;
    size_t map_len;
    uint64_t segment;

    if (!r || len < RNS_RES_HASH_LEN || memcmp(plain, r->hash, RNS_RES_HASH_LEN) != 0
        || !r->waiting_for_hmu)
        return;
    r->last_activity = now;
    r->retries_left = MAX_RETRIES;
    if (rns_hmu_unpack(plain + RNS_RES_HASH_LEN, len - RNS_RES_HASH_LEN, &segment,
                       &map, &map_len) != 0
        || hashmap_update(c, segment, map, map_len, now) != 0)
        cancel(c, now, "invalid hashmap update");
}

void
rns_resource_cancelled(struct rns_client *c, const uint8_t *plain, size_t len)
{
    if (c->resource && len >= RNS_RES_HASH_LEN
        && memcmp(plain, c->resource->hash, RNS_RES_HASH_LEN) == 0) {
        rlog(c, RNS_LOG_DEBUG, "the hub cancelled its resource transfer");
        rns_resource_free(c);
    }
}

static void
assemble(struct rns_client *c, double now)
{
    struct rns_resource *r = c->resource;
    uint8_t proof[2 * RNS_RES_HASH_LEN], *data;
    size_t len, off = 0, meta;

    if (rns_resource_decode(c->key, r->flags, r->stream, r->size, r->random, r->hash,
                            &data, &len) != 0) {
        cancel(c, now, "the data does not match its hash");
        return;
    }
    /* proof: the resource hash, then SHA-256(data + resource hash) */
    memcpy(proof, r->hash, RNS_RES_HASH_LEN);
    cr_sha256_2(data, len, r->hash, RNS_RES_HASH_LEN, proof + RNS_RES_HASH_LEN);
    if (r->flags & RNS_RES_F_METADATA) {
        /* a 3-byte length and msgpack metadata come first; we skip them */
        meta = len >= 3 ? ((size_t)data[0] << 16 | (size_t)data[1] << 8 | data[2]) : 0;
        if (len < 3 || meta > len - 3) {
            free(data);
            cancel(c, now, "malformed metadata");
            return;
        }
        off = 3 + meta;
    }
    rns_link_packet(c, RNS_PT_PROOF, RNS_CTX_RESOURCE_PRF, proof, sizeof(proof), 0, now);
    rlog(c, RNS_LOG_DEBUG, "resource of %zu bytes received", len - off);
    rns_resource_free(c);
    if (c->cb.resource)
        c->cb.resource(c->ctx, data + off, len - off);
    free(data);
}

void
rns_resource_part(struct rns_client *c, const uint8_t *data, size_t len, double now)
{
    struct rns_resource *r = c->resource;
    uint8_t h[CR_SHA256_LEN];
    size_t i, end, cp;

    if (!r)
        return;
    r->last_activity = now;
    r->retries_left = MAX_RETRIES;
    cr_sha256_2(data, len, r->random, RNS_RES_RANDOM_LEN, h);
    i = (size_t)(r->consecutive + 1);
    end = i + r->window < r->total_parts ? i + r->window : r->total_parts;
    for (; i < end; i++) {
        if (!(r->part[i] & P_MAPPED) || (r->part[i] & P_RECEIVED)
            || memcmp(r->hashmap + i * RNS_RES_MAPHASH_LEN, h, RNS_RES_MAPHASH_LEN) != 0
            || len != part_len(r, i))
            continue;
        memcpy(r->stream + i * r->sdu, data, len);
        r->part[i] |= P_RECEIVED;
        r->received++;
        if (r->outstanding)
            r->outstanding--;
        cp = (size_t)(r->consecutive + 1);
        while (cp < r->total_parts && (r->part[cp] & P_RECEIVED))
            r->consecutive = (long)cp++;
    }
    if (r->received == r->total_parts) {
        assemble(c, now);
    } else if (r->outstanding == 0) {
        if (r->window < r->window_max) {
            r->window++;
            if (r->window - r->window_min > WINDOW_FLEXIBILITY - 1)
                r->window_min++;
        }
        request_next(c, now);
    }
}

void
rns_resource_tick(struct rns_client *c, double now)
{
    struct rns_resource *r = c->resource;
    double wait;

    if (!r)
        return;
    wait = c->rtt * (PART_TIMEOUT_FACTOR + (double)r->outstanding) + RETRY_GRACE
           + TIMEOUT_GRACE + (MAX_RETRIES - r->retries_left) * PER_RETRY_DELAY;
    if (now < r->last_activity + wait)
        return;
    if (r->retries_left <= 0) {
        cancel(c, now, "timed out");
        return;
    }
    if (r->window > r->window_min) {
        r->window--;
        if (r->window_max > r->window_min) {
            r->window_max--;
            if (r->window_max - r->window > WINDOW_FLEXIBILITY - 1)
                r->window_max--;
        }
    }
    r->retries_left--;
    r->waiting_for_hmu = 0;
    request_next(c, now);
}
