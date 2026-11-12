/*
 * fuzz.c - throws random and mutated input at everything that parses bytes
 * from the network: HDLC deframing, packet parsing, the link state machine,
 * CBOR decoding, RRC envelope handling and resource transfers (msgpack
 * advertisements, parts, hashmap updates, bz2). Run it under ASan/UBSan.
 *
 *   fuzz [iterations] [seed]
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/cbor.h"
#include "../src/crypto.h"
#include "../src/hdlc.h"
#include "../src/resource.h"
#include "../src/rns.h"
#include "../src/rrc.h"
#include "vectors.h"

static struct rns_client client, rclient;
static struct rrc_session session;
static size_t events;

static int sink_send(void *ctx, const uint8_t *p, size_t n) { return 0; }
static void sink_state(void *ctx, enum rns_state s, const char *r) {}
static void sink_data(void *ctx, const uint8_t *d, size_t n)
{
    rrc_session_data(&session, d, n, 1.0);
}
static void sink_log(void *ctx, int l, const char *m) {}
static void sink_resource(void *ctx, const uint8_t *d, size_t n)
{
    rrc_session_resource(&session, d, n, 1.0);
}
static size_t sink_mdu(void *ctx) { return RNS_LINK_MDU; }
static void sink_event(void *ctx, const struct rrc_event *ev)
{
    size_t i;
    /* touch every field, so ASan sees any bad pointer */
    if (ev->room) events += strlen(ev->room);
    if (ev->nick) events += strlen(ev->nick);
    if (ev->text) events += strlen(ev->text);
    if (ev->src) events += ev->src[15];
    for (i = 0; i < ev->n_members; i++)
        events += ev->members[i][0];
}
static void sink_frame(void *ctx, const uint8_t *f, size_t n)
{
    rns_client_inbound(&client, f, n, 1.0);
}

static uint32_t rng;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }

static void
mutate(uint8_t *buf, size_t *len, size_t cap)
{
    int k, ops = 1 + rnd() % 6;
    for (k = 0; k < ops; k++) {
        size_t pos = *len ? rnd() % *len : 0;
        switch (rnd() % 5) {
        case 0: if (*len) buf[pos] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: if (*len) buf[pos] = (uint8_t)rnd(); break;
        case 2: if (*len) *len = rnd() % *len; break;
        case 3: if (*len < cap) { memmove(buf + pos + 1, buf + pos, *len - pos); buf[pos] = (uint8_t)rnd(); (*len)++; } break;
        case 4: if (*len) buf[pos] = (uint8_t)(0x18 + rnd() % 8 + ((rnd() % 8) << 5)); break;
        }
    }
}

int
main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 200000, i;
    struct rns_callbacks rcb = { sink_send, sink_state, sink_data, sink_log, sink_resource };
    struct rrc_callbacks scb = { sink_send, sink_mdu, sink_event };
    struct rns_identity id;
    struct hdlc_rx rx;
    struct cb_item pool[256], *root;
    uint8_t hub[RNS_HASH_LEN], buf[1024];
    size_t len;
    const uint8_t *seeds[] = { V_CBOR_ENV, V_CBOR_WELCOME, V_CBOR_RES_ENV };
    size_t seed_len[] = { sizeof(V_CBOR_ENV), sizeof(V_CBOR_WELCOME), sizeof(V_CBOR_RES_ENV) };
    const uint8_t *advs[] = { V_RES1_ADV, V_RES2_ADV, V_RES3_ADV, V_RES_BIG_ADV, V_RES3_HMU };
    size_t adv_len[] = { sizeof(V_RES1_ADV), sizeof(V_RES2_ADV), sizeof(V_RES3_ADV),
                         sizeof(V_RES_BIG_ADV), sizeof(V_RES3_HMU) };

    rng = argc > 2 ? (uint32_t)atol(argv[2]) : 0x12345678u;
    rns_identity_from_bytes(&id, V_ID_PRV);
    memcpy(hub, V_HUB_DEST, RNS_HASH_LEN);
    rns_client_init(&client, &id, hub, 0, &rcb, NULL);
    rns_client_init(&rclient, &id, hub, 0, &rcb, NULL);
    memcpy(rclient.link_id, V_RES_LINK_ID, RNS_HASH_LEN);
    memcpy(rclient.key, V_RES_KEY, sizeof(rclient.key));
    rclient.rtt = 0.01;
    rrc_session_init(&session, id.hash, "fuzz", &scb, NULL);
    hdlc_rx_init(&rx);

    for (i = 0; i < iters; i++) {
        int which = (int)(rnd() % 6);
        if (which == 0 || which == 1) {
            /* CBOR / RRC envelopes, mutated from real ones */
            int s = (int)(rnd() % 3);
            len = seed_len[s];
            memcpy(buf, seeds[s], len);
            mutate(buf, &len, sizeof(buf));
            if (cb_decode(buf, len, pool, 256, &root) == 0)
                cb_map_uint(root, 6);
            session.welcomed = 1;
            rrc_session_data(&session, buf, len, 1.0);
        } else if (which == 2) {
            /* packets: force each link state so every handler is reached */
            len = 19 + rnd() % 480;
            for (size_t k = 0; k < len; k++)
                buf[k] = (uint8_t)rnd();
            buf[0] &= 0x7f;
            buf[1] &= 0x3f;
            client.state = (enum rns_state)(1 + rnd() % 3);
            if (rnd() % 2)
                memcpy(buf + 2, client.link_id, RNS_HASH_LEN);
            else
                memcpy(buf + 2, hub, RNS_HASH_LEN);
            rns_client_inbound(&client, buf, len, 1.0);
            rns_client_tick(&client, 1.0 + (double)(rnd() % 1000));
        } else if (which == 4) {
            /* resource packets: advertisements, hashmap updates and parts,
             * mutated, then encrypted where RNS encrypts them so they get
             * past the link's HMAC */
            uint8_t pkt[RNS_MTU];
            int k = (int)(rnd() % 5), part = rnd() % 3 == 0;
            long n;
            if (part) {
                len = 1 + rnd() % (RNS_MTU - 19 - 1);   /* V_RES2_STREAM is longer */
                memcpy(buf, V_RES2_STREAM, len);
                if (rnd() % 2)
                    mutate(buf, &len, RNS_MTU - 19);
            } else {
                len = adv_len[k];
                memcpy(buf, advs[k], len);
                mutate(buf, &len, RNS_MTU - 19 - 64);
            }
            pkt[0] = 0x0c;
            pkt[1] = 0;
            memcpy(pkt + 2, V_RES_LINK_ID, RNS_HASH_LEN);
            pkt[18] = part ? RNS_CTX_RESOURCE
                    : (uint8_t)(k == 4 ? RNS_CTX_RESOURCE_HMU : RNS_CTX_RESOURCE_ADV);
            if (part) {
                memcpy(pkt + 19, buf, len);
                n = (long)len;
            } else {
                n = cr_token_encrypt(V_RES_KEY, NULL, buf, len, pkt + 19);
            }
            rclient.state = RNS_ACTIVE;
            rclient.mtu = rnd() % 8 ? RNS_MTU : (int)(rnd() % 600);
            if (n > 0 && len)
                rns_client_inbound(&rclient, pkt, 19 + (size_t)n, 1.0);
            rns_client_tick(&rclient, 1.0 + (double)(rnd() % 100));
            {
                struct rns_adv adv;
                uint64_t seg;
                const uint8_t *m;
                size_t ml;
                rns_adv_unpack(buf, len, &adv);
                rns_hmu_unpack(buf, len, &seg, &m, &ml);
            }
        } else if (which == 5) {
            /* resource data: bz2 and the hash check, and RRC matching */
            uint8_t *out = NULL, r[4] = { 0 }, h[32] = { 0 };
            size_t olen;
            len = sizeof(V_BZ2_BOMB) + 4;
            memset(buf, 0, 4);
            memcpy(buf + 4, V_BZ2_BOMB, sizeof(V_BZ2_BOMB));
            mutate(buf, &len, sizeof(buf));
            if (rns_resource_decode(V_RES_KEY, rnd() % 4, buf, len, r, h, &out, &olen) == 0)
                free(out);
            session.welcomed = 1;
            rrc_session_data(&session, V_CBOR_RES_ENV, sizeof(V_CBOR_RES_ENV), 1.0);
            rrc_session_resource(&session, buf, len, 1.0);
        } else {
            /* raw bytes through the deframer */
            len = rnd() % sizeof(buf);
            for (size_t k = 0; k < len; k++)
                buf[k] = (rnd() % 8 == 0) ? 0x7e : (uint8_t)rnd();
            client.state = RNS_ACTIVE;
            hdlc_rx_feed(&rx, buf, len, sink_frame, NULL);
        }
    }
    rrc_session_free(&session);
    rns_client_wipe(&client);
    rns_client_wipe(&rclient);
    printf("%ld iterations, %zu event bytes touched\n", iters, events);
    return 0;
}
