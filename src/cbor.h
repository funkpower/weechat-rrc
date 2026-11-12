/*
 * cbor.h - the subset of CBOR (RFC 8949) that RRC uses
 *
 * The decoder parses untrusted input into a fixed pool of items: no heap
 * allocation, bounded depth, and every length checked against the input.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_CBOR_H
#define RRC_CBOR_H

#include <stddef.h>
#include <stdint.h>

/* ---- encoder ---- */

struct cb_writer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int overflow;
};

void cb_writer_init(struct cb_writer *w, uint8_t *buf, size_t cap);
void cb_put_uint(struct cb_writer *w, uint64_t v);
void cb_put_bytes(struct cb_writer *w, const uint8_t *p, size_t n);
void cb_put_text(struct cb_writer *w, const char *s, size_t n);
void cb_put_array(struct cb_writer *w, size_t n);
void cb_put_map(struct cb_writer *w, size_t n);
void cb_put_bool(struct cb_writer *w, int v);
void cb_put_null(struct cb_writer *w);
/* Append an already encoded item. */
void cb_put_raw(struct cb_writer *w, const uint8_t *p, size_t n);

/* ---- decoder ---- */

enum cb_type {
    CB_UINT,
    CB_NINT,      /* value is -1 - u */
    CB_BYTES,
    CB_TEXT,
    CB_ARRAY,
    CB_MAP,
    CB_BOOL,
    CB_NULL,
    CB_FLOAT,
    CB_OTHER,     /* undefined, unknown simple values */
};

struct cb_item {
    enum cb_type type;
    uint64_t u;                 /* UINT, NINT, BOOL */
    double f;                   /* FLOAT */
    const uint8_t *p;           /* BYTES, TEXT: points into the input */
    size_t len;                 /* BYTES, TEXT: byte length */
    size_t count;               /* ARRAY: items; MAP: pairs */
    struct cb_item *items;      /* ARRAY: count items; MAP: 2*count, key then value */
    const uint8_t *raw;         /* the item's own encoding, within the input */
    size_t raw_len;
};

#define CB_MAX_DEPTH 16

/* Decode exactly one item spanning all of data[0..len). Returns 0 on success. */
int cb_decode(const uint8_t *data, size_t len,
              struct cb_item *pool, size_t pool_size, struct cb_item **root);

/* Map lookup by unsigned integer key; NULL when absent or not a map. */
const struct cb_item *cb_map_uint(const struct cb_item *map, uint64_t key);

#endif
