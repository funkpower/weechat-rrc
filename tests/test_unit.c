/*
 * test_unit.c - checks the C primitives against vectors from Python RNS
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/cbor.h"
#include "../src/crypto.h"
#include "../src/hdlc.h"
#include "../src/micron.h"
#include "../src/resource.h"
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
    {
        static const uint8_t rlo[] = { 'a', 0xe2, 0x80, 0xae, 'b' };
        rrc_clean_text(rlo, sizeof(rlo), out, sizeof(out));
        CHECK(strcmp(out, "ab") == 0, "bidi override stripped");
    }
    CHECK(rrc_normalize_room("  LoBBy ", out, sizeof(out)) == 5 && strcmp(out, "lobby") == 0,
          "normalize room");
    CHECK(rrc_normalize_room("   ", out, sizeof(out)) == 0, "empty room");
}

static int noop_send(void *ctx, const uint8_t *p, size_t n) { return 0; }

static void
test_keepalive_not_deduplicated(void)
{
    struct rns_identity id;
    struct rns_client c;
    struct rns_callbacks cb = { noop_send, NULL, NULL, NULL, NULL };
    uint8_t pkt[RNS_HEADER_MINSIZE + 1];

    rns_identity_from_bytes(&id, V_ID_PRV);
    rns_client_init(&c, &id, V_HUB_DEST, 0, &cb, NULL);
    c.state = RNS_ACTIVE;
    memset(c.link_id, 0xab, RNS_HASH_LEN);
    pkt[0] = 0x0c;   /* HEADER_1, LINK, DATA */
    pkt[1] = 0;
    memcpy(pkt + 2, c.link_id, RNS_HASH_LEN);
    pkt[18] = RNS_CTX_KEEPALIVE;
    pkt[19] = 0xfe;
    rns_client_inbound(&c, pkt, sizeof(pkt), 100.0);
    CHECK(c.last_inbound == 100.0, "first keepalive counts as inbound");
    rns_client_inbound(&c, pkt, sizeof(pkt), 200.0);
    CHECK(c.last_inbound == 200.0, "an identical later keepalive counts too");
}

static const char *
fake_color(const char *name)
{
    static char ring[8][40];
    static int i;
    i = (i + 1) % 8;
    snprintf(ring[i], sizeof(ring[i]), "<%s>", name);
    return ring[i];
}

static void
test_micron(void)
{
    char out[512];

    CHECK(micron_xterm256(255, 0, 0) == 196, "xterm red");
    CHECK(micron_xterm256(0, 0, 0) == 16, "xterm black");
    CHECK(micron_xterm256(128, 128, 128) == 244, "xterm grey");

    CHECK(micron_render("\xc2\xa6" "Bf00  " "\xc2\xa6" "b x", out, sizeof(out), fake_color) == 1
          && strcmp(out, "<default,196>  <default,default> x<reset>") == 0, "broken-bar colour");
    CHECK(micron_render("`F0f0hi`f", out, sizeof(out), fake_color) == 1
          && strcmp(out, "<46,default>hi<default,default><reset>") == 0, "backtick colour");
    CHECK(micron_render("use `foo` and `bar`", out, sizeof(out), fake_color) == 0
          && strcmp(out, "use `foo` and `bar`") == 0, "prose backticks untouched");
    CHECK(micron_render("\xc2\xa6" "!bold" "\xc2\xa6" "! \xc2\xa6" "Q", out, sizeof(out), fake_color) == 1
          && strcmp(out, "<bold>bold<-bold> \xc2\xa6Q<reset>") == 0, "bold toggle, unknown tag kept");
    CHECK(micron_render("\xc2\xa6" "BT102030x", out, sizeof(out), fake_color) == 1
          && strstr(out, "x<reset>") != NULL, "24-bit colour");
    CHECK(micron_render("\xc2\xa6" "Bzzz", out, sizeof(out), fake_color) == 0, "bad hex is text");
    CHECK(micron_present("a \xc2\xa6" "F123 b") && !micron_present("a `b` c"), "presence");
    {
        char small[12];
        micron_render("\xc2\xa6" "Bf00\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88", small, sizeof(small), fake_color);
        CHECK(strlen(small) < sizeof(small), "truncated output stays terminated");
    }
}

static void
test_unicode_room(void)
{
    char out[64];

    setlocale(LC_CTYPE, "C.UTF-8");
    CHECK(rrc_normalize_room(" \xc3\x84rger ", out, sizeof(out)) && strcmp(out, "\xc3\xa4rger") == 0,
          "non-ASCII room lowered like Python");
    CHECK(rrc_normalize_room("\xd0\x9b\xd0\x9e\xd0\x91\xd0\x91\xd0\x98", out, sizeof(out))
          && strcmp(out, "\xd0\xbb\xd0\xbe\xd0\xb1\xd0\xb1\xd0\xb8") == 0, "Cyrillic room");
}

/* ---- resources ---- */

/* The text tests/gen_vectors.py made the resources from. */
static uint8_t *
greeting(int lines, size_t *len)
{
    uint8_t *buf = malloc((size_t)lines * 40 + 1);
    size_t n = 0;
    int i;

    for (i = 0; i < lines; i++)
        n += (size_t)sprintf((char *)buf + n, "line %d of a long greeting\n", i);
    *len = n;
    return buf;
}

#define RES_SENT_MAX 64
static uint8_t res_sent[RES_SENT_MAX][RNS_MTU];
static size_t res_sent_len[RES_SENT_MAX];
static size_t res_sent_n;
static uint8_t *res_got;
static size_t res_got_len;
static int res_got_count;

static uint8_t res_cancelled[32];
static int res_cancel_count;

static int
res_send(void *ctx, const uint8_t *p, size_t n)
{
    uint8_t plain[RNS_MTU];

    /* remember RESOURCE_RCL: the hash of the resource we turned down */
    if (n > 19 && p[18] == RNS_CTX_RESOURCE_RCL
        && cr_token_decrypt(V_RES_KEY, p + 19, n - 19, plain) == 32) {
        memcpy(res_cancelled, plain, 32);
        res_cancel_count++;
    }
    if (res_sent_n < RES_SENT_MAX) {
        memcpy(res_sent[res_sent_n], p, n);
        res_sent_len[res_sent_n++] = n;
    }
    return 0;
}

static void
res_deliver(void *ctx, const uint8_t *data, size_t len)
{
    free(res_got);
    res_got = malloc(len ? len : 1);
    memcpy(res_got, data, len);
    res_got_len = len;
    res_got_count++;
}

static void
res_client(struct rns_client *c)
{
    static struct rns_identity id;
    struct rns_callbacks cb = { res_send, NULL, NULL, NULL, res_deliver };

    rns_identity_from_bytes(&id, V_ID_PRV);
    rns_client_init(c, &id, V_HUB_DEST, 0, &cb, NULL);
    c->state = RNS_ACTIVE;
    memcpy(c->link_id, V_RES_LINK_ID, RNS_HASH_LEN);
    memcpy(c->key, V_RES_KEY, 64);
    c->rtt = 0.01;
    c->activated_at = c->last_inbound = 100.0;
    c->keepalive = c->stale_time = 1000.0;
    res_sent_n = 0;
    res_cancel_count = 0;
    free(res_got);
    res_got = NULL;
    res_got_count = 0;
}

/* Hand the client a link packet from the hub. */
static void
res_feed(struct rns_client *c, uint8_t context, const uint8_t *data, size_t len, int encrypt)
{
    uint8_t pkt[RNS_MTU];
    long n = (long)len;

    pkt[0] = 0x0c;   /* HEADER_1, LINK, DATA */
    pkt[1] = 0;
    memcpy(pkt + 2, V_RES_LINK_ID, RNS_HASH_LEN);
    pkt[18] = context;
    if (encrypt)
        n = cr_token_encrypt(V_RES_KEY, NULL, data, len, pkt + 19);
    else
        memcpy(pkt + 19, data, len);
    rns_client_inbound(c, pkt, 19 + (size_t)n, 100.0);
}

/* Play the hub's side of a transfer, as Resource.request() does: answer
 * each request with the parts it names and, when asked, the next hashmap
 * segment. Returns the client's proof packet's data, or NULL. */
static const uint8_t *
res_transfer(struct rns_client *c, const uint8_t *adv_buf, size_t adv_len,
             const uint8_t *stream, size_t stream_len, const uint8_t *hmu, size_t hmu_len,
             int corrupt_part)
{
    static uint8_t proof[64];
    uint8_t plain[RNS_MTU], *map;
    struct rns_adv adv;
    size_t map_len, sdu = RNS_MTU - 36, round, i, k, j;
    int got_proof = 0;

    if (rns_adv_unpack(adv_buf, adv_len, &adv) != 0)
        return NULL;
    /* the whole hashmap: the advertisement's, then the update's */
    map = malloc(adv.n * 4);
    memcpy(map, adv.m, adv.m_len);
    map_len = adv.m_len;
    if (hmu) {
        uint64_t seg;
        const uint8_t *m2;
        size_t m2_len;
        if (rns_hmu_unpack(hmu + 32, hmu_len - 32, &seg, &m2, &m2_len) == 0
            && map_len + m2_len <= adv.n * 4) {
            memcpy(map + map_len, m2, m2_len);
            map_len += m2_len;
        }
    }
    res_sent_n = 0;
    res_feed(c, RNS_CTX_RESOURCE_ADV, adv_buf, adv_len, 1);
    for (round = 0; round < 200 && res_sent_n && !got_proof; round++) {
        size_t pending = res_sent_n;
        static uint8_t batch[RES_SENT_MAX][RNS_MTU];
        static size_t batch_len[RES_SENT_MAX];
        memcpy(batch, res_sent, sizeof(batch));
        memcpy(batch_len, res_sent_len, sizeof(batch_len));
        res_sent_n = 0;
        for (k = 0; k < pending; k++) {
            uint8_t *p = batch[k];
            long n;
            if (p[0] == 0x0f && p[18] == RNS_CTX_RESOURCE_PRF && batch_len[k] == 19 + 64) {
                memcpy(proof, p + 19, 64);
                got_proof = 1;
                continue;
            }
            if (p[18] != RNS_CTX_RESOURCE_REQ)
                continue;
            n = cr_token_decrypt(V_RES_KEY, p + 19, batch_len[k] - 19, plain);
            if (n < 33)
                continue;
            i = plain[0] == 0xff ? 5 : 1;
            CHECK_MEM(plain + i, adv.h, 32, "request names the resource");
            for (i += 32; i + 4 <= (size_t)n; i += 4) {
                for (j = 0; j < map_len / 4; j++) {
                    if (memcmp(map + 4 * j, plain + i, 4) == 0) {
                        size_t off = j * sdu, len = off + sdu <= stream_len ? sdu : stream_len - off;
                        uint8_t part[RNS_MTU];
                        memcpy(part, stream + off, len);
                        if ((int)j == corrupt_part)
                            part[0] ^= 1;
                        res_feed(c, RNS_CTX_RESOURCE, part, len, 0);
                        break;
                    }
                }
            }
            if (plain[0] == 0xff && hmu)
                res_feed(c, RNS_CTX_RESOURCE_HMU, hmu, hmu_len, 1);
        }
    }
    free(map);
    return got_proof ? proof : NULL;
}

/* rebuild a resource's encrypted stream from its data, IV and prefix */
static uint8_t *
res_stream(int lines, const uint8_t iv[16], const uint8_t prefix[4], size_t *len)
{
    size_t dlen;
    uint8_t *data = greeting(lines, &dlen), *plain = malloc(dlen + 4), *out = malloc(dlen + 4 + 64);
    long n;

    memcpy(plain, prefix, 4);
    memcpy(plain + 4, data, dlen);
    n = cr_token_encrypt(V_RES_KEY, iv, plain, dlen + 4, out);
    *len = n > 0 ? (size_t)n : 0;
    free(data);
    free(plain);
    return out;
}

static int
sent_cancel(const uint8_t hash[32])
{
    return res_cancel_count == 1 && memcmp(res_cancelled, hash, 32) == 0;
}

static void
test_resource(void)
{
    struct rns_client c;
    struct rns_adv adv;
    const uint8_t *proof;
    uint8_t *stream, *data, sha[32], *out;
    size_t slen, dlen, olen;

    /* the advertisement */
    data = greeting(V_RES1_LINES, &dlen);
    CHECK(rns_adv_unpack(V_RES1_ADV, sizeof(V_RES1_ADV), &adv) == 0, "unpack advertisement");
    CHECK(adv.d == dlen && adv.f == RNS_RES_F_ENCRYPTED && adv.i == 1 && adv.l == 1
          && !adv.has_q && adv.m_len == 4 * adv.n && adv.n == (adv.t + 463) / 464,
          "advertisement fields");
    CHECK_MEM(adv.h, V_RES1_PROOF, 32, "advertised hash");
    CHECK(rns_adv_unpack(V_RES1_ADV, sizeof(V_RES1_ADV) - 1, &adv) != 0, "truncated advertisement");

    /* a whole transfer, as rrcd sends it */
    stream = res_stream(V_RES1_LINES, V_RES1_IV, V_RES1_PREFIX, &slen);
    cr_sha256(stream, slen, sha);
    CHECK_MEM(sha, V_RES1_STREAM_SHA, 32, "rebuilt stream matches RNS");
    res_client(&c);
    proof = res_transfer(&c, V_RES1_ADV, sizeof(V_RES1_ADV), stream, slen, NULL, 0, -1);
    CHECK(proof && memcmp(proof, V_RES1_PROOF, 64) == 0, "proof matches RNS");
    CHECK(res_got_count == 1 && res_got_len == dlen && memcmp(res_got, data, dlen) == 0,
          "resource data delivered");
    CHECK(c.resource == NULL, "transfer state freed");

    /* data that doesn't match the resource hash: no proof, no data, and
     * the transfer is cancelled */
    {
        uint8_t bad[sizeof(V_RES1_ADV)], *h = NULL;
        size_t at;
        memcpy(bad, V_RES1_ADV, sizeof(bad));
        for (at = 0; at + 32 <= sizeof(bad) && !h; at++)
            if (memcmp(bad + at, V_RES1_PROOF, 32) == 0)
                h = bad + at;
        CHECK(h != NULL, "hash in the advertisement");
        if (h) {
            h[31] ^= 1;
            res_client(&c);
            proof = res_transfer(&c, bad, sizeof(bad), stream, slen, NULL, 0, -1);
            CHECK(!proof && res_got_count == 0 && !c.resource && sent_cancel(h),
                  "hash mismatch: cancelled");
        }
    }

    /* a corrupted part */
    res_client(&c);
    {
        /* the map hash covers the part, so a flipped bit is never accepted:
         * the requests time out and the receiver gives up */
        double t;
        proof = res_transfer(&c, V_RES1_ADV, sizeof(V_RES1_ADV), stream, slen, NULL, 0, 1);
        CHECK(!proof && res_got_count == 0 && c.resource, "corrupt part not taken");
        for (t = 101.0; t < 400.0 && c.resource; t += 1.0)
            rns_client_tick(&c, t);
        CHECK(!c.resource && sent_cancel(V_RES1_PROOF), "gave up and cancelled");
    }
    free(stream);
    free(data);

    /* compressed */
    data = greeting(V_RES2_LINES, &dlen);
    res_client(&c);
    proof = res_transfer(&c, V_RES2_ADV, sizeof(V_RES2_ADV), V_RES2_STREAM, sizeof(V_RES2_STREAM),
                         NULL, 0, -1);
    CHECK(proof && memcmp(proof, V_RES2_PROOF, 64) == 0, "compressed: proof");
    CHECK(res_got_count == 1 && res_got_len == dlen && memcmp(res_got, data, dlen) == 0,
          "compressed: data");
    free(data);

    /* more parts than one advertisement maps: a hashmap update */
    data = greeting(V_RES3_LINES, &dlen);
    stream = res_stream(V_RES3_LINES, V_RES3_IV, V_RES3_PREFIX, &slen);
    cr_sha256(stream, slen, sha);
    CHECK_MEM(sha, V_RES3_STREAM_SHA, 32, "rebuilt stream 3 matches RNS");
    res_client(&c);
    proof = res_transfer(&c, V_RES3_ADV, sizeof(V_RES3_ADV), stream, slen,
                         V_RES3_HMU, sizeof(V_RES3_HMU), -1);
    CHECK(proof && memcmp(proof, V_RES3_PROOF, 64) == 0, "hashmap update: proof");
    CHECK(res_got_count == 1 && res_got_len == dlen && memcmp(res_got, data, dlen) == 0,
          "hashmap update: data");
    free(stream);
    free(data);

    /* too large: refused at once, with RESOURCE_RCL */
    res_client(&c);
    res_feed(&c, RNS_CTX_RESOURCE_ADV, V_RES_BIG_ADV, sizeof(V_RES_BIG_ADV), 1);
    CHECK(!c.resource && sent_cancel(V_RES_BIG_HASH), "too large: rejected");

    /* the hub cancelling its own transfer */
    res_client(&c);
    res_feed(&c, RNS_CTX_RESOURCE_ADV, V_RES1_ADV, sizeof(V_RES1_ADV), 1);
    CHECK(c.resource != NULL, "transfer started");
    res_feed(&c, RNS_CTX_RESOURCE_ICL, V_RES1_PROOF, 32, 1);
    CHECK(c.resource == NULL, "initiator cancel");

    /* closing the link frees a transfer in progress */
    res_feed(&c, RNS_CTX_RESOURCE_ADV, V_RES1_ADV, sizeof(V_RES1_ADV), 1);
    CHECK(c.resource != NULL, "transfer restarted");
    rns_client_close(&c, 100.0, "test");
    CHECK(c.resource == NULL, "close frees the transfer");

    /* a decompression bomb is cut off */
    {
        uint8_t buf[sizeof(V_BZ2_BOMB) + 4] = { 0 }, h[32] = { 0 }, r[4] = { 0 };
        memcpy(buf + 4, V_BZ2_BOMB, sizeof(V_BZ2_BOMB));
        CHECK(rns_resource_decode(V_RES_KEY, RNS_RES_F_COMPRESSED, buf, sizeof(buf), r, h,
                                  &out, &olen) != 0 && !out, "bz2 output bounded");
    }
    free(res_got);
    res_got = NULL;
}

static struct rrc_session res_session;
static char res_text[4096];
static const uint8_t *res_src;
static int res_events;

static size_t res_mdu(void *ctx) { return RNS_LINK_MDU; }
static void
res_event(void *ctx, const struct rrc_event *ev)
{
    res_events++;
    if (ev->type == RRC_EV_NOTICE && ev->text) {
        snprintf(res_text, sizeof(res_text), "%s", ev->text);
        res_src = ev->src;
    }
}

static void
test_resource_envelope(void)
{
    struct rrc_callbacks cb = { noop_send, res_mdu, res_event };
    struct rns_identity id;
    uint8_t *data;
    size_t dlen;

    rns_identity_from_bytes(&id, V_ID_PRV);
    rrc_session_init(&res_session, id.hash, "t", &cb, NULL);
    data = greeting(V_RES1_LINES, &dlen);

    /* unannounced data is dropped */
    rrc_session_resource(&res_session, data, dlen, 10.0);
    CHECK(res_events == 0, "unannounced resource dropped");

    rrc_session_data(&res_session, V_CBOR_RES_ENV, sizeof(V_CBOR_RES_ENV), 10.0);
    CHECK(res_events == 0, "envelope alone shows nothing");
    rrc_session_resource(&res_session, data, dlen - 1, 11.0);
    CHECK(res_events == 0, "a different size does not match");
    rrc_session_resource(&res_session, data, dlen, 11.0);
    CHECK(res_events == 1 && strlen(res_text) == dlen && memcmp(res_text, data, dlen) == 0,
          "announced resource shown as a notice");
    CHECK(res_src && memcmp(res_src, res_session.res_expect[0].src, 16) == 0, "notice source");
    rrc_session_resource(&res_session, data, dlen, 12.0);
    CHECK(res_events == 1, "an envelope is used once");

    /* expired */
    rrc_session_data(&res_session, V_CBOR_RES_ENV, sizeof(V_CBOR_RES_ENV), 20.0);
    rrc_session_resource(&res_session, data, dlen, 60.0);
    CHECK(res_events == 1, "expired envelope");

    /* the hash must match */
    rrc_session_data(&res_session, V_CBOR_RES_ENV, sizeof(V_CBOR_RES_ENV), 70.0);
    data[0] ^= 1;
    rrc_session_resource(&res_session, data, dlen, 71.0);
    CHECK(res_events == 1, "hash mismatch dropped");
    free(data);
    rrc_session_free(&res_session);
}

int
main(void)
{
    test_resource();
    test_resource_envelope();
    test_unicode_room();
    test_micron();
    test_keepalive_not_deduplicated();
    test_identity();
    test_kdf_and_token();
    test_cbor();
    test_hdlc();
    test_text();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
