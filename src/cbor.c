/*
 * cbor.c - the subset of CBOR (RFC 8949) that RRC uses
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>

#include "cbor.h"

/* ---- encoder ---- */

void
cb_writer_init(struct cb_writer *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = 0;
}

static void
put_raw(struct cb_writer *w, const void *p, size_t n)
{
    if (w->overflow || n > w->cap - w->len) {
        w->overflow = 1;
        return;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

static void
put_head(struct cb_writer *w, uint8_t major, uint64_t v)
{
    uint8_t b[9];
    size_t n, i;

    if (v < 24) {
        b[0] = (uint8_t)((major << 5) | v);
        n = 1;
    } else if (v <= 0xff) {
        b[0] = (uint8_t)((major << 5) | 24);
        n = 2;
    } else if (v <= 0xffff) {
        b[0] = (uint8_t)((major << 5) | 25);
        n = 3;
    } else if (v <= 0xffffffffULL) {
        b[0] = (uint8_t)((major << 5) | 26);
        n = 5;
    } else {
        b[0] = (uint8_t)((major << 5) | 27);
        n = 9;
    }
    for (i = n - 1; i >= 1; i--) {
        b[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    put_raw(w, b, n);
}

void cb_put_uint(struct cb_writer *w, uint64_t v) { put_head(w, 0, v); }
void cb_put_array(struct cb_writer *w, size_t n) { put_head(w, 4, n); }
void cb_put_map(struct cb_writer *w, size_t n) { put_head(w, 5, n); }

void
cb_put_bytes(struct cb_writer *w, const uint8_t *p, size_t n)
{
    put_head(w, 2, n);
    put_raw(w, p, n);
}

void
cb_put_text(struct cb_writer *w, const char *s, size_t n)
{
    put_head(w, 3, n);
    put_raw(w, s, n);
}

void
cb_put_bool(struct cb_writer *w, int v)
{
    uint8_t b = v ? 0xf5 : 0xf4;
    put_raw(w, &b, 1);
}

void
cb_put_raw(struct cb_writer *w, const uint8_t *p, size_t n)
{
    put_raw(w, p, n);
}

void
cb_put_null(struct cb_writer *w)
{
    uint8_t b = 0xf6;
    put_raw(w, &b, 1);
}

/* ---- decoder ---- */

struct cb_reader {
    const uint8_t *p;
    size_t len;
    size_t pos;
    struct cb_item *pool;
    size_t pool_size;
    size_t used;
};

static struct cb_item *
alloc_items(struct cb_reader *r, size_t n)
{
    struct cb_item *it;

    if (n > r->pool_size - r->used)
        return NULL;
    it = r->pool + r->used;
    r->used += n;
    memset(it, 0, n * sizeof(*it));
    return it;
}

static int
read_uint(struct cb_reader *r, uint8_t info, uint64_t *out)
{
    size_t n, i;
    uint64_t v = 0;

    if (info < 24) {
        *out = info;
        return 0;
    }
    switch (info) {
    case 24: n = 1; break;
    case 25: n = 2; break;
    case 26: n = 4; break;
    case 27: n = 8; break;
    default: return -1;  /* 28-30 reserved, 31 indefinite: unsupported */
    }
    if (n > r->len - r->pos)
        return -1;
    for (i = 0; i < n; i++)
        v = (v << 8) | r->p[r->pos++];
    *out = v;
    return 0;
}

static double
half_to_double(uint16_t h)
{
    int e = (h >> 10) & 0x1f, m = h & 0x3ff;
    double v;

    if (e == 0)
        v = m * (1.0 / 16777216.0);           /* subnormal: m * 2^-24 */
    else if (e == 31)
        v = m ? 0.0 / 0.0 : 1.0 / 0.0;
    else {
        v = (double)(m | 0x400);
        e -= 25;
        while (e > 0) { v *= 2.0; e--; }
        while (e < 0) { v *= 0.5; e++; }
    }
    return (h & 0x8000) ? -v : v;
}

static int decode_value(struct cb_reader *r, struct cb_item *it, int depth);

static int
decode_item(struct cb_reader *r, struct cb_item *it, int depth)
{
    size_t start = r->pos;
    int rc = decode_value(r, it, depth);

    if (rc == 0) {
        it->raw = r->p + start;
        it->raw_len = r->pos - start;
    }
    return rc;
}

static int
decode_value(struct cb_reader *r, struct cb_item *it, int depth)
{
    uint8_t ib, major, info;
    uint64_t v;
    size_t i;

    if (depth > CB_MAX_DEPTH || r->pos >= r->len)
        return -1;
    ib = r->p[r->pos++];
    major = ib >> 5;
    info = ib & 0x1f;

    if (major == 7) {
        switch (info) {
        case 20: it->type = CB_BOOL; it->u = 0; return 0;
        case 21: it->type = CB_BOOL; it->u = 1; return 0;
        case 22: it->type = CB_NULL; return 0;
        case 25: case 26: case 27: {
            size_t n = info == 25 ? 2 : info == 26 ? 4 : 8;
            uint64_t bits = 0;
            if (n > r->len - r->pos)
                return -1;
            for (i = 0; i < n; i++)
                bits = (bits << 8) | r->p[r->pos++];
            it->type = CB_FLOAT;
            if (n == 2) {
                it->f = half_to_double((uint16_t)bits);
            } else if (n == 4) {
                float f;
                uint32_t b32 = (uint32_t)bits;
                memcpy(&f, &b32, 4);
                it->f = f;
            } else {
                memcpy(&it->f, &bits, 8);
            }
            return 0;
        }
        default:
            if (info == 24) {
                if (r->pos >= r->len)
                    return -1;
                r->pos++;
            } else if (info > 24) {
                return -1;  /* break / reserved */
            }
            it->type = CB_OTHER;
            return 0;
        }
    }

    if (read_uint(r, info, &v) != 0)
        return -1;

    switch (major) {
    case 0:
        it->type = CB_UINT;
        it->u = v;
        return 0;
    case 1:
        it->type = CB_NINT;
        it->u = v;
        return 0;
    case 2:
    case 3:
        if (v > r->len - r->pos)
            return -1;
        it->type = major == 2 ? CB_BYTES : CB_TEXT;
        it->p = r->p + r->pos;
        it->len = (size_t)v;
        r->pos += (size_t)v;
        return 0;
    case 4:
        /* each item takes at least one byte of input */
        if (v > r->len - r->pos)
            return -1;
        it->type = CB_ARRAY;
        it->count = (size_t)v;
        it->items = alloc_items(r, it->count);
        if (it->count && !it->items)
            return -1;
        for (i = 0; i < it->count; i++)
            if (decode_item(r, &it->items[i], depth + 1) != 0)
                return -1;
        return 0;
    case 5:
        if (v > (r->len - r->pos) / 2)
            return -1;
        it->type = CB_MAP;
        it->count = (size_t)v;
        it->items = alloc_items(r, it->count * 2);
        if (it->count && !it->items)
            return -1;
        for (i = 0; i < it->count * 2; i++)
            if (decode_item(r, &it->items[i], depth + 1) != 0)
                return -1;
        return 0;
    case 6:
        /* tag: ignore it, the tagged item stands in its place */
        return decode_value(r, it, depth + 1);
    }
    return -1;
}

int
cb_decode(const uint8_t *data, size_t len,
          struct cb_item *pool, size_t pool_size, struct cb_item **root)
{
    struct cb_reader r = { data, len, 0, pool, pool_size, 0 };
    struct cb_item *it;

    it = alloc_items(&r, 1);
    if (!it || decode_item(&r, it, 0) != 0 || r.pos != len)
        return -1;
    *root = it;
    return 0;
}

const struct cb_item *
cb_map_uint(const struct cb_item *map, uint64_t key)
{
    size_t i;

    if (!map || map->type != CB_MAP)
        return NULL;
    for (i = 0; i < map->count; i++) {
        const struct cb_item *k = &map->items[2 * i];
        if (k->type == CB_UINT && k->u == key)
            return &map->items[2 * i + 1];
    }
    return NULL;
}
