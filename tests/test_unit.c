/*
 * test_unit.c - checks the C primitives against vectors from Python RNS
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "../src/cbor.h"
#include "../src/crypto.h"
#include "../src/hdlc.h"
#include "../src/rns.h"
#include "../src/rrc.h"
#include "vectors.h"

static int failures, checks;

#define CHECK(cond, what) do { \
    checks++; \
    if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, what); } \
} while (0)

#define CHECK_MEM(a, b, n, what) CHECK(memcmp((a), (b), (n)) == 0, what)

static void
test_identity(void)
{
    struct rns_identity id;
    uint8_t dest[RNS_HASH_LEN], sig[64];

    CHECK(rns_identity_from_bytes(&id, V_ID_PRV) == 0, "identity from bytes");
    CHECK_MEM(id.pub, V_ID_PUB, 64, "identity public key");
    CHECK_MEM(id.hash, V_ID_HASH, 16, "identity hash");

    rns_destination_hash("rrc.hub", id.hash, dest);
    CHECK_MEM(dest, V_HUB_DEST, 16, "rrc.hub destination hash");
    rns_destination_hash("rnstransport.path.request", NULL, dest);
    CHECK_MEM(dest, V_PR_DEST, 16, "path request destination hash");

    CHECK(cr_ed25519_sign(id.ed_seed, V_SIG_MSG, sizeof(V_SIG_MSG), sig) == 0, "sign");
    CHECK_MEM(sig, V_SIG, 64, "ed25519 signature matches RNS");
    CHECK(cr_ed25519_verify(id.pub + 32, V_SIG_MSG, sizeof(V_SIG_MSG), V_SIG) == 1, "verify");
    sig[0] ^= 1;
    CHECK(cr_ed25519_verify(id.pub + 32, V_SIG_MSG, sizeof(V_SIG_MSG), sig) == 0,
          "verify rejects a bad signature");
}

static void
test_kdf_and_token(void)
{
    struct rns_identity id;
    uint8_t shared[32], out[64], buf[256];
    long n;

    rns_identity_from_bytes(&id, V_ID_PRV);
    CHECK(cr_x25519_shared(id.x_prv, V_PEER_XPUB, shared) == 0, "x25519");
    CHECK_MEM(shared, V_SHARED, 32, "x25519 shared secret");

    cr_hkdf(shared, 32, V_HKDF_SALT, sizeof(V_HKDF_SALT), NULL, 0, out, 64);
    CHECK_MEM(out, V_HKDF_OUT, 64, "hkdf with salt");
    cr_hkdf(shared, 32, NULL, 0, NULL, 0, out, 64);
    CHECK_MEM(out, V_HKDF_NOSALT, 64, "hkdf without salt");

    n = cr_token_decrypt(V_TOKEN_KEY, V_TOKEN, sizeof(V_TOKEN), buf);
    CHECK(n == (long)sizeof(V_TOKEN_PLAIN), "token decrypt length");
    CHECK(n > 0 && memcmp(buf, V_TOKEN_PLAIN, (size_t)n) == 0, "token decrypt");

    {
        static const uint8_t zero_iv[16] = { 0 };
        n = cr_token_encrypt(V_TOKEN_KEY, zero_iv, V_TOKEN_PLAIN, sizeof(V_TOKEN_PLAIN), buf);
        CHECK(n == (long)sizeof(V_TOKEN_FIXED_IV), "token encrypt length");
        CHECK_MEM(buf, V_TOKEN_FIXED_IV, sizeof(V_TOKEN_FIXED_IV), "token encrypt matches RNS");
    }
    memcpy(buf, V_TOKEN, sizeof(V_TOKEN));
    buf[20] ^= 1;
    {
        uint8_t plain[256];
        CHECK(cr_token_decrypt(V_TOKEN_KEY, buf, sizeof(V_TOKEN), plain) < 0,
              "token decrypt rejects tampering");
    }
}

static void
test_cbor(void)
{
    struct cb_item pool[64], *root;
    const struct cb_item *it, *lim;
    uint8_t buf[64];
    struct cb_writer w;

    CHECK(cb_decode(V_CBOR_ENV, sizeof(V_CBOR_ENV), pool, 64, &root) == 0, "decode envelope");
    CHECK(root->type == CB_MAP && root->count == 8, "envelope is an 8-field map");
    it = cb_map_uint(root, 3);
    CHECK(it && it->type == CB_UINT && it->u == 1737849600000ULL, "timestamp");
    it = cb_map_uint(root, 6);
    CHECK(it && it->type == CB_TEXT && it->len == strlen("hello \xc3\xa9 \xe2\x96\x88"), "body");
    it = cb_map_uint(root, 4);
    CHECK(it && it->type == CB_BYTES && it->len == 16, "source hash");

    CHECK(cb_decode(V_CBOR_WELCOME, sizeof(V_CBOR_WELCOME), pool, 64, &root) == 0, "decode welcome");
    lim = cb_map_uint(cb_map_uint(cb_map_uint(root, 6), 3) ? cb_map_uint(root, 6) : NULL, 3);
    it = cb_map_uint(lim, 2);
    CHECK(it && it->type == CB_UINT && it->u == 350, "welcome limit max_msg_body_bytes");

    /* truncated input and trailing garbage are rejected */
    CHECK(cb_decode(V_CBOR_ENV, sizeof(V_CBOR_ENV) - 1, pool, 64, &root) != 0, "truncated");
    {
        uint8_t bad[sizeof(V_CBOR_ENV) + 1];
        memcpy(bad, V_CBOR_ENV, sizeof(V_CBOR_ENV));
        bad[sizeof(V_CBOR_ENV)] = 0;
        CHECK(cb_decode(bad, sizeof(bad), pool, 64, &root) != 0, "trailing byte");
    }
    /* a huge declared length must not be trusted */
    {
        static const uint8_t huge[] = { 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        CHECK(cb_decode(huge, sizeof(huge), pool, 64, &root) != 0, "huge array length");
    }
    /* deep nesting is bounded */
    {
        uint8_t deep[40];
        memset(deep, 0x81, sizeof(deep));
        deep[39] = 0x00;
        CHECK(cb_decode(deep, sizeof(deep), pool, 64, &root) != 0, "nesting depth");
    }

    cb_writer_init(&w, buf, sizeof(buf));
    cb_put_map(&w, 2);
    cb_put_uint(&w, 3);
    cb_put_uint(&w, 1737849600000ULL);
    cb_put_uint(&w, 5);
    cb_put_text(&w, "lobby", 5);
    CHECK(!w.overflow && w.len == 1 + 1 + 9 + 1 + 6, "encoded size");
    CHECK(cb_decode(buf, w.len, pool, 64, &root) == 0, "roundtrip");
    it = cb_map_uint(root, 5);
    CHECK(it && it->type == CB_TEXT && it->len == 5 && memcmp(it->p, "lobby", 5) == 0,
          "roundtrip text");
}

static int frames_seen;
static uint8_t last_frame[64];
static size_t last_len;

static void
on_frame(void *ctx, const uint8_t *f, size_t len)
{
    (void)ctx;
    frames_seen++;
    last_len = len < sizeof(last_frame) ? len : sizeof(last_frame);
    memcpy(last_frame, f, last_len);
}

static void
test_hdlc(void)
{
    static const uint8_t data[] = { 0x01, 0x7e, 0x02, 0x7d, 0x03 };
    uint8_t framed[16];
    struct hdlc_rx rx;
    size_t n, i;

    n = hdlc_frame(data, sizeof(data), framed);
    CHECK(n == sizeof(data) + 2 + 2, "framed size");
    hdlc_rx_init(&rx);
    /* byte at a time, to cover frames split across reads */
    for (i = 0; i < n; i++)
        hdlc_rx_feed(&rx, framed + i, 1, on_frame, NULL);
    CHECK(frames_seen == 1 && last_len == sizeof(data)
          && memcmp(last_frame, data, sizeof(data)) == 0, "deframe");
    hdlc_rx_feed(&rx, framed, n, on_frame, NULL);
    CHECK(frames_seen == 2, "back-to-back frames");
}

static void
test_text(void)
{
    char out[64];
    static const uint8_t in[] = { 'a', 0x1b, '[', '3', '1', 'm', 0x03, '4', 'b', 0xff, 'c',
                                  0xc2, 0x85, 0xe2, 0x96, 0x88, '\t', '\n' };

    rrc_clean_text(in, sizeof(in), out, sizeof(out));
    CHECK(strcmp(out, "a[31m4b\xef\xbf\xbd" "c\xe2\x96\x88 \n") == 0, "clean text");
    CHECK(rrc_normalize_room("  LoBBy ", out, sizeof(out)) == 5 && strcmp(out, "lobby") == 0,
          "normalize room");
    CHECK(rrc_normalize_room("   ", out, sizeof(out)) == 0, "empty room");
}

int
main(void)
{
    test_identity();
    test_kdf_and_token();
    test_cbor();
    test_hdlc();
    test_text();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
