/*
 * rrc_resource.c - RRC text sent as a Reticulum resource
 *
 * rrcd sends text longer than one packet (a long greeting) as a resource:
 * first a RESOURCE_ENVELOPE (type 50) saying what is coming (kind, size,
 * SHA-256, encoding, room), then the resource itself. The link layer hands
 * us the received data; we match it to its envelope by size and hash, as
 * rrcd and NomadNet do, and deliver it as a NOTICE.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "resource.h"
#include "rrc.h"

/* RESOURCE_ENVELOPE body keys */
#define B_RES_ID 0
#define B_RES_KIND 1
#define B_RES_SIZE 2
#define B_RES_SHA256 3
#define B_RES_ENCODING 4

#define KIND_OTHER 0
#define KIND_NOTICE 1
#define KIND_MOTD 2

/* rrcd's resource_expectation_ttl_s */
#define EXPECT_TTL 30.0

static int
text_is(const struct cb_item *it, const char *s)
{
    return it && it->type == CB_TEXT && it->len == strlen(s) && memcmp(it->p, s, it->len) == 0;
}

void
rrc_res_envelope(struct rrc_session *s, const struct rrc_event *ev,
                 const struct cb_item *body, double now)
{
    const struct cb_item *kind, *size, *sha;
    struct rrc_res_expect *e = NULL;
    size_t i;

    if (!body || body->type != CB_MAP)
        return;
    kind = cb_map_uint(body, B_RES_KIND);
    size = cb_map_uint(body, B_RES_SIZE);
    sha = cb_map_uint(body, B_RES_SHA256);
    if (!kind || kind->type != CB_TEXT || !size || size->type != CB_UINT
        || size->u == 0 || size->u > RNS_RESOURCE_MAX)
        return;
    /* a free or expired slot, else the one closest to expiring */
    for (i = 0; i < RRC_RES_EXPECT; i++) {
        struct rrc_res_expect *x = &s->res_expect[i];
        if (!x->used || x->expires <= now) {
            e = x;
            break;
        }
        if (!e || x->expires < e->expires)
            e = x;
    }
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->kind = text_is(kind, "notice") ? KIND_NOTICE : text_is(kind, "motd") ? KIND_MOTD
            : KIND_OTHER;
    e->size = (size_t)size->u;
    if (sha && sha->type == CB_BYTES && sha->len == sizeof(e->sha256)) {
        memcpy(e->sha256, sha->p, sizeof(e->sha256));
        e->has_sha256 = 1;
    }
    if (ev->src) {
        memcpy(e->src, ev->src, RNS_HASH_LEN);
        e->has_src = 1;
    }
    if (ev->room)
        snprintf(e->room, sizeof(e->room), "%s", ev->room);
    e->expires = now + EXPECT_TTL;
    /* B_RES_ENCODING: rrcd always sends UTF-8; anything else is shown as
     * UTF-8 too, invalid bytes replaced */
}

void
rrc_session_resource(struct rrc_session *s, const uint8_t *data, size_t len, double now)
{
    struct rrc_res_expect *e = NULL;
    struct rrc_event ev;
    uint8_t sha[CR_SHA256_LEN];
    char *text;
    size_t i;

    cr_sha256(data, len, sha);
    for (i = 0; i < RRC_RES_EXPECT; i++) {
        struct rrc_res_expect *x = &s->res_expect[i];
        if (x->used && x->expires > now && x->size == len
            && (!x->has_sha256 || memcmp(x->sha256, sha, sizeof(sha)) == 0)) {
            e = x;
            break;
        }
    }
    if (!e)
        return;   /* nothing announced it */
    e->used = 0;
    if (e->kind == KIND_OTHER || len > RNS_RESOURCE_MAX)
        return;
    /* cleaning turns each invalid byte into three */
    text = malloc(3 * len + 1);
    if (!text)
        return;
    rrc_clean_text(data, len, text, 3 * len + 1);
    if (text[0]) {
        memset(&ev, 0, sizeof(ev));
        ev.type = RRC_EV_NOTICE;
        ev.room = e->room[0] ? e->room : NULL;
        ev.src = e->has_src ? e->src : NULL;
        ev.own = ev.src && memcmp(ev.src, s->self, RNS_HASH_LEN) == 0;
        ev.text = text;
        s->cb.event(s->ctx, &ev);
    }
    free(text);
}
