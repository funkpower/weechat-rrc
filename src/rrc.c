/*
 * rrc.c - Reticulum Relay Chat session
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbor.h"
#include "crypto.h"
#include "rrc.h"

#ifndef RRC_CLIENT_VERSION
#define RRC_CLIENT_VERSION "0.1.0"
#endif

/* HELLO body keys */
#define B_HELLO_NAME 0
#define B_HELLO_VER 1
#define B_HELLO_CAPS 2
/* WELCOME body keys */
#define B_WELCOME_HUB 0
#define B_WELCOME_VER 1
#define B_WELCOME_LIMITS 3
/* limits keys */
#define L_MAX_NICK 0
#define L_MAX_ROOM 1
#define L_MAX_BODY 2
#define L_MAX_ROOMS 3
#define L_RATE 4
/* capabilities */
#define CAP_ACTION 1

#define HELLO_MAX_TRIES 5
#define DECODE_POOL 512
#define MAX_QUEUE 4096

/* ---- text ---- */

void
rrc_clean_text(const uint8_t *in, size_t len, char *out, size_t out_size)
{
    size_t i = 0, o = 0, n, k;
    uint32_t cp;
    uint8_t b;

    if (!out_size)
        return;
    while (i < len) {
        b = in[i];
        if (b < 0x80) {
            i++;
            if (b == '\t')
                b = ' ';
            if ((b < 0x20 && b != '\n') || b == 0x7f)
                continue;
            if (o + 1 >= out_size)
                break;
            out[o++] = (char)b;
            continue;
        }
        if ((b & 0xe0) == 0xc0) { n = 2; cp = b & 0x1f; }
        else if ((b & 0xf0) == 0xe0) { n = 3; cp = b & 0x0f; }
        else if ((b & 0xf8) == 0xf0) { n = 4; cp = b & 0x07; }
        else { n = 0; cp = 0; }
        if (n && i + n <= len) {
            for (k = 1; k < n; k++) {
                if ((in[i + k] & 0xc0) != 0x80)
                    break;
                cp = (cp << 6) | (in[i + k] & 0x3f);
            }
            if (k == n
                && !(n == 2 && cp < 0x80) && !(n == 3 && cp < 0x800)
                && !(n == 4 && cp < 0x10000) && cp <= 0x10ffff
                && !(cp >= 0xd800 && cp <= 0xdfff)) {
                i += n;
                if (cp >= 0x80 && cp <= 0x9f)
                    continue;   /* C1 controls */
                if (o + n >= out_size)
                    break;
                memcpy(out + o, in + i - n, n);
                o += n;
                continue;
            }
        }
        /* invalid sequence: one byte becomes U+FFFD */
        i++;
        if (o + 3 >= out_size)
            break;
        out[o++] = (char)0xef;
        out[o++] = (char)0xbf;
        out[o++] = (char)0xbd;
    }
    out[o] = '\0';
}

size_t
rrc_normalize_room(const char *in, char *out, size_t out_size)
{
    size_t start = 0, end = strlen(in), i, n;

    while (start < end && (in[start] == ' ' || in[start] == '\t'))
        start++;
    while (end > start && (in[end - 1] == ' ' || in[end - 1] == '\t'))
        end--;
    n = end - start;
    if (n == 0 || n >= out_size)
        return 0;
    for (i = 0; i < n; i++) {
        char ch = in[start + i];
        out[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
    }
    out[n] = '\0';
    return n;
}

static void
item_text(const struct cb_item *it, char *out, size_t out_size)
{
    if (it && it->type == CB_TEXT)
        rrc_clean_text(it->p, it->len, out, out_size);
    else if (out_size)
        out[0] = '\0';
}

/* ---- sizes ---- */

static size_t
head_len(size_t n)
{
    return n < 24 ? 1 : n < 256 ? 2 : n < 65536 ? 3 : 5;
}

/* map(1) + v(2) + t(2) + id(10) + ts(10) + src(18) */
#define ENV_FIXED 43

size_t
rrc_max_body(struct rrc_session *s, const char *room)
{
    size_t mdu = s->cb.mdu(s->ctx), cost = ENV_FIXED, nick = strlen(s->nick), body;

    if (room)
        cost += 1 + head_len(strlen(room)) + strlen(room);
    if (nick)
        cost += 1 + head_len(nick) + nick;
    cost += 1;   /* body key */
    if (mdu <= cost + 3)
        return 0;
    body = mdu - cost;
    body -= head_len(body);
    if (head_len(body) < head_len(body + head_len(body)))
        body--;
    if (s->limits.max_msg_body_bytes && body > s->limits.max_msg_body_bytes)
        body = s->limits.max_msg_body_bytes;
    return body;
}

/* ---- encoding ---- */

enum body_kind { BODY_NONE, BODY_TEXT, BODY_RAW, BODY_HELLO };

static void
put_envelope(struct rrc_session *s, struct cb_writer *w, int type, const char *room,
             enum body_kind kind, const void *body, size_t body_len, int with_nick,
             uint8_t id_out[8])
{
    uint8_t id[8];
    struct timespec ts;
    uint64_t ms;
    size_t fields = 5;
    int nick = with_nick && s->nick[0];

    cr_random(id, sizeof(id));
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;

    if (room)
        fields++;
    if (kind != BODY_NONE)
        fields++;
    if (nick)
        fields++;
    cb_put_map(w, fields);
    cb_put_uint(w, RRC_K_V);
    cb_put_uint(w, RRC_VERSION);
    cb_put_uint(w, RRC_K_T);
    cb_put_uint(w, (uint64_t)type);
    cb_put_uint(w, RRC_K_ID);
    cb_put_bytes(w, id, sizeof(id));
    cb_put_uint(w, RRC_K_TS);
    cb_put_uint(w, ms);
    cb_put_uint(w, RRC_K_SRC);
    cb_put_bytes(w, s->self, RNS_HASH_LEN);
    if (room) {
        cb_put_uint(w, RRC_K_ROOM);
        cb_put_text(w, room, strlen(room));
    }
    switch (kind) {
    case BODY_TEXT:
        cb_put_uint(w, RRC_K_BODY);
        cb_put_text(w, body, body_len);
        break;
    case BODY_RAW:
        cb_put_uint(w, RRC_K_BODY);
        cb_put_raw(w, body, body_len);
        break;
    case BODY_HELLO:
        cb_put_uint(w, RRC_K_BODY);
        cb_put_map(w, 3);
        cb_put_uint(w, B_HELLO_NAME);
        cb_put_text(w, "weechat-rrc", 11);
        cb_put_uint(w, B_HELLO_VER);
        cb_put_text(w, RRC_CLIENT_VERSION, strlen(RRC_CLIENT_VERSION));
        cb_put_uint(w, B_HELLO_CAPS);
        cb_put_map(w, 1);
        cb_put_uint(w, CAP_ACTION);
        cb_put_bool(w, 1);
        break;
    case BODY_NONE:
        break;
    }
    if (nick) {
        cb_put_uint(w, RRC_K_NICK);
        cb_put_text(w, s->nick, strlen(s->nick));
    }
    if (id_out)
        memcpy(id_out, id, sizeof(id));
}

static void
remember_sent(struct rrc_session *s, const uint8_t id[8])
{
    memcpy(s->sent_ids[s->sent_next], id, 8);
    s->sent_next = (s->sent_next + 1) % RRC_SENT_IDS;
}

static int
was_sent(struct rrc_session *s, const uint8_t *id)
{
    size_t i;

    for (i = 0; i < RRC_SENT_IDS; i++)
        if (memcmp(s->sent_ids[i], id, 8) == 0)
            return 1;
    return 0;
}

/* ---- queue and rate limit ---- */

static double
rate_per_min(struct rrc_session *s)
{
    unsigned r = s->limits.rate_limit_msgs_per_minute;
    /* stay a little under the hub's own bucket */
    return (r ? r : 240) * 0.9;
}

static void
refill(struct rrc_session *s, double now)
{
    double cap = rate_per_min(s);

    if (now > s->refill_at) {
        s->tokens += (now - s->refill_at) * cap / 60.0;
        s->refill_at = now;
    }
    if (s->tokens > cap)
        s->tokens = cap;
}

static void
flush(struct rrc_session *s, double now)
{
    struct rrc_queued *q;

    if (!s->welcomed)
        return;
    refill(s, now);
    while ((q = s->queue_head) && s->tokens >= 1.0) {
        if (q->len > s->cb.mdu(s->ctx)) {
            /* the link shrank under it; nothing to do but drop it */
        } else if (s->cb.send(s->ctx, q->data, q->len) != 0) {
            break;
        }
        s->tokens -= 1.0;
        s->queue_head = q->next;
        if (!s->queue_head)
            s->queue_tail = NULL;
        s->queued--;
        free(q);
    }
}

static int
enqueue(struct rrc_session *s, struct cb_writer *w, double now, const char **err)
{
    struct rrc_queued *q;

    if (w->overflow || w->len > s->cb.mdu(s->ctx)) {
        *err = "message too long for one packet";
        return -1;
    }
    if (s->queued >= MAX_QUEUE) {
        *err = "send queue full";
        return -1;
    }
    q = malloc(sizeof(*q));
    if (!q) {
        *err = "out of memory";
        return -1;
    }
    q->next = NULL;
    q->len = w->len;
    memcpy(q->data, w->buf, w->len);
    if (s->queue_tail)
        s->queue_tail->next = q;
    else
        s->queue_head = q;
    s->queue_tail = q;
    s->queued++;
    flush(s, now);
    return 0;
}

/* ---- pending joins and parts ---- */

static void
pending_add(char (*set)[RRC_MAX_ROOM], const char *room)
{
    int i, free_slot = -1;

    for (i = 0; i < 16; i++) {
        if (strcmp(set[i], room) == 0)
            return;
        if (!set[i][0] && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        free_slot = 0;
    snprintf(set[free_slot], RRC_MAX_ROOM, "%s", room);
}

/* Remove room from the set; returns 1 if it was there. */
static int
pending_take(char (*set)[RRC_MAX_ROOM], const char *room)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (set[i][0] && strcmp(set[i], room) == 0) {
            set[i][0] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ---- session ---- */

void
rrc_session_init(struct rrc_session *s, const uint8_t self[RNS_HASH_LEN],
                 const char *nick, const struct rrc_callbacks *cb, void *ctx)
{
    memset(s, 0, sizeof(*s));
    s->cb = *cb;
    s->ctx = ctx;
    memcpy(s->self, self, RNS_HASH_LEN);
    rrc_set_nick(s, nick);
}

void
rrc_session_free(struct rrc_session *s)
{
    struct rrc_queued *q, *next;

    for (q = s->queue_head; q; q = next) {
        next = q->next;
        free(q);
    }
    s->queue_head = s->queue_tail = NULL;
    s->queued = 0;
}

void
rrc_set_nick(struct rrc_session *s, const char *nick)
{
    size_t n = nick ? strlen(nick) : 0;
    size_t max = s->limits.max_nick_bytes ? s->limits.max_nick_bytes : 32;

    if (n > max)
        n = max;
    if (n >= sizeof(s->nick))
        n = sizeof(s->nick) - 1;
    /* don't cut a UTF-8 sequence in half */
    while (n > 0 && ((uint8_t)nick[n] & 0xc0) == 0x80)
        n--;
    if (n)
        memcpy(s->nick, nick, n);
    s->nick[n] = '\0';
}

static void
send_hello(struct rrc_session *s, double now)
{
    uint8_t buf[RNS_LINK_MDU];
    struct cb_writer w;

    cb_writer_init(&w, buf, sizeof(buf));
    put_envelope(s, &w, RRC_T_HELLO, NULL, BODY_HELLO, NULL, 0, 1, NULL);
    if (!w.overflow)
        s->cb.send(s->ctx, buf, w.len);
    s->hello_tries++;
    s->hello_sent = now;
}

void
rrc_session_start(struct rrc_session *s, double rtt, double now)
{
    s->welcomed = 0;
    s->hello_tries = 0;
    memset(s->pending_join, 0, sizeof(s->pending_join));
    memset(s->pending_part, 0, sizeof(s->pending_part));
    s->hello_interval = rtt * 6.0;
    if (s->hello_interval < 5.0)
        s->hello_interval = 5.0;
    s->tokens = rate_per_min(s);
    s->refill_at = now;
    send_hello(s, now);
}

void
rrc_session_tick(struct rrc_session *s, double now)
{
    struct rrc_event ev;

    if (!s->welcomed && s->hello_tries > 0 && now >= s->hello_sent + s->hello_interval) {
        if (s->hello_tries >= HELLO_MAX_TRIES) {
            s->hello_tries = 0;
            memset(&ev, 0, sizeof(ev));
            ev.type = RRC_EV_HELLO_TIMEOUT;
            s->cb.event(s->ctx, &ev);
            return;
        }
        send_hello(s, now);
    }
    flush(s, now);
}

int
rrc_join(struct rrc_session *s, const char *room, double now, const char **err)
{
    uint8_t buf[RNS_LINK_MDU];
    char r[RRC_MAX_ROOM];
    struct cb_writer w;

    if (!rrc_normalize_room(room, r, sizeof(r))) {
        *err = "invalid room name";
        return -1;
    }
    cb_writer_init(&w, buf, sizeof(buf));
    put_envelope(s, &w, RRC_T_JOIN, r, BODY_NONE, NULL, 0, 1, NULL);
    if (enqueue(s, &w, now, err) != 0)
        return -1;
    pending_add(s->pending_join, r);
    return 0;
}

int
rrc_part(struct rrc_session *s, const char *room, double now, const char **err)
{
    uint8_t buf[RNS_LINK_MDU];
    char r[RRC_MAX_ROOM];
    struct cb_writer w;

    if (!rrc_normalize_room(room, r, sizeof(r))) {
        *err = "invalid room name";
        return -1;
    }
    cb_writer_init(&w, buf, sizeof(buf));
    put_envelope(s, &w, RRC_T_PART, r, BODY_NONE, NULL, 0, 0, NULL);
    if (enqueue(s, &w, now, err) != 0)
        return -1;
    pending_add(s->pending_part, r);
    return 0;
}

int
rrc_say(struct rrc_session *s, int type, const char *room, const char *text,
        double now, const char **err)
{
    uint8_t buf[RNS_LINK_MDU], id[8];
    char r[RRC_MAX_ROOM];
    struct cb_writer w;
    size_t len = strlen(text);

    if (room && !rrc_normalize_room(room, r, sizeof(r))) {
        *err = "invalid room name";
        return -1;
    }
    if (!len) {
        *err = "empty message";
        return -1;
    }
    if (len > rrc_max_body(s, room ? r : NULL)) {
        *err = "message too long";
        return -1;
    }
    cb_writer_init(&w, buf, sizeof(buf));
    put_envelope(s, &w, type, room ? r : NULL, BODY_TEXT, text, len, 1, id);
    if (enqueue(s, &w, now, err) != 0)
        return -1;
    remember_sent(s, id);
    return 0;
}

int
rrc_ping(struct rrc_session *s, double now, const char **err)
{
    uint8_t buf[RNS_LINK_MDU], body[8], enc[16];
    struct cb_writer w, bw;
    int i, slot = 0;

    cr_random(body, sizeof(body));
    for (i = 0; i < RRC_PINGS; i++) {
        if (!s->pings[i].used) {
            slot = i;
            break;
        }
        if (s->pings[i].at < s->pings[slot].at)
            slot = i;
    }
    memcpy(s->pings[slot].body, body, sizeof(body));
    s->pings[slot].at = now;
    s->pings[slot].used = 1;

    cb_writer_init(&bw, enc, sizeof(enc));
    cb_put_bytes(&bw, body, sizeof(body));
    cb_writer_init(&w, buf, sizeof(buf));
    put_envelope(s, &w, RRC_T_PING, NULL, BODY_RAW, enc, bw.len, 0, NULL);
    return enqueue(s, &w, now, err);
}

static unsigned
limit_value(const struct cb_item *limits, uint64_t key, unsigned current)
{
    const struct cb_item *v = cb_map_uint(limits, key);

    if (v && v->type == CB_UINT && v->u > 0 && v->u < 1000000)
        return (unsigned)v->u;
    return current;
}

static size_t
member_list(const struct cb_item *body, uint8_t (*out)[RNS_HASH_LEN], size_t max)
{
    size_t i, n = 0;

    if (!body || body->type != CB_ARRAY)
        return 0;
    for (i = 0; i < body->count && n < max; i++) {
        const struct cb_item *e = &body->items[i];
        if (e->type == CB_BYTES && e->len == RNS_HASH_LEN)
            memcpy(out[n++], e->p, RNS_HASH_LEN);
    }
    return n;
}

void
rrc_session_data(struct rrc_session *s, const uint8_t *data, size_t len, double now)
{
    struct cb_item pool[DECODE_POOL], *env;
    const struct cb_item *v, *t, *id, *ts, *src, *room, *body, *nick;
    char room_s[RRC_MAX_ROOM], nick_s[RRC_MAX_NICK], text_s[RRC_MAX_TEXT];
    char hub_s[RRC_MAX_NICK], ver_s[RRC_MAX_NICK];
    uint8_t members[RRC_MAX_MEMBERS][RNS_HASH_LEN];
    struct rrc_event ev;
    size_t i;

    if (cb_decode(data, len, pool, DECODE_POOL, &env) != 0 || env->type != CB_MAP)
        return;
    v = cb_map_uint(env, RRC_K_V);
    t = cb_map_uint(env, RRC_K_T);
    if (!t || t->type != CB_UINT)
        return;
    if (v && (v->type != CB_UINT || v->u != RRC_VERSION))
        return;
    id = cb_map_uint(env, RRC_K_ID);
    ts = cb_map_uint(env, RRC_K_TS);
    src = cb_map_uint(env, RRC_K_SRC);
    room = cb_map_uint(env, RRC_K_ROOM);
    body = cb_map_uint(env, RRC_K_BODY);
    nick = cb_map_uint(env, RRC_K_NICK);

    memset(&ev, 0, sizeof(ev));
    if (src && src->type == CB_BYTES && src->len == RNS_HASH_LEN)
        ev.src = src->p;
    if (room && room->type == CB_TEXT) {
        char raw[RRC_MAX_ROOM];
        item_text(room, raw, sizeof(raw));
        if (rrc_normalize_room(raw, room_s, sizeof(room_s)))
            ev.room = room_s;
    }
    if (nick && nick->type == CB_TEXT) {
        item_text(nick, nick_s, sizeof(nick_s));
        if (nick_s[0])
            ev.nick = nick_s;
    }
    if (ts && ts->type == CB_UINT)
        ev.ts = ts->u;
    ev.own = ev.src && memcmp(ev.src, s->self, RNS_HASH_LEN) == 0;

    switch (t->u) {
    case RRC_T_WELCOME:
        s->welcomed = 1;
        s->hello_tries = 0;
        if (body && body->type == CB_MAP) {
            const struct cb_item *lim = cb_map_uint(body, B_WELCOME_LIMITS);
            item_text(cb_map_uint(body, B_WELCOME_HUB), hub_s, sizeof(hub_s));
            item_text(cb_map_uint(body, B_WELCOME_VER), ver_s, sizeof(ver_s));
            if (hub_s[0])
                ev.hub_name = hub_s;
            if (ver_s[0])
                ev.hub_version = ver_s;
            if (lim && lim->type == CB_MAP) {
                s->limits.max_nick_bytes = limit_value(lim, L_MAX_NICK, s->limits.max_nick_bytes);
                s->limits.max_room_name_bytes = limit_value(lim, L_MAX_ROOM, s->limits.max_room_name_bytes);
                s->limits.max_msg_body_bytes = limit_value(lim, L_MAX_BODY, s->limits.max_msg_body_bytes);
                s->limits.max_rooms_per_session = limit_value(lim, L_MAX_ROOMS, s->limits.max_rooms_per_session);
                s->limits.rate_limit_msgs_per_minute = limit_value(lim, L_RATE, s->limits.rate_limit_msgs_per_minute);
            }
        }
        snprintf(s->hub_name, sizeof(s->hub_name), "%s", hub_s);
        s->tokens = rate_per_min(s);
        s->refill_at = now;
        ev.type = RRC_EV_WELCOME;
        s->cb.event(s->ctx, &ev);
        flush(s, now);
        return;

    case RRC_T_JOINED:
    case RRC_T_PARTED:
        if (!ev.room)
            return;
        ev.n_members = member_list(body, members, RRC_MAX_MEMBERS);
        ev.members = (const uint8_t (*)[RNS_HASH_LEN])members;
        ev.own = pending_take(t->u == RRC_T_JOINED ? s->pending_join : s->pending_part,
                              ev.room);
        if (!ev.own)
            for (i = 0; i < ev.n_members; i++)
                if (ev.n_members == 1 && memcmp(members[i], s->self, RNS_HASH_LEN) == 0)
                    ev.own = 1;
        /* about someone else: the envelope's nick is theirs, not the hub's */
        ev.type = t->u == RRC_T_JOINED ? RRC_EV_JOINED : RRC_EV_PARTED;
        s->cb.event(s->ctx, &ev);
        return;

    case RRC_T_MSG:
    case RRC_T_ACTION:
    case RRC_T_NOTICE:
        /* A busy room's JOINED carries a member list too big for one packet,
         * and rrcd then never sends it. Traffic for a room we asked to join
         * means we are in it. */
        if (ev.room && pending_take(s->pending_join, ev.room)) {
            struct rrc_event joined;
            memset(&joined, 0, sizeof(joined));
            joined.type = RRC_EV_JOINED;
            joined.room = ev.room;
            joined.own = 1;
            joined.ts = ev.ts;
            s->cb.event(s->ctx, &joined);
        }
        if (!body || body->type != CB_TEXT)
            return;
        if (ev.own && id && id->type == CB_BYTES && id->len == 8 && was_sent(s, id->p))
            return;   /* the hub's echo of something we already showed */
        item_text(body, text_s, sizeof(text_s));
        ev.text = text_s;
        ev.type = t->u == RRC_T_MSG ? RRC_EV_MSG
                : t->u == RRC_T_ACTION ? RRC_EV_ACTION : RRC_EV_NOTICE;
        s->cb.event(s->ctx, &ev);
        return;

    case RRC_T_ERROR:
        if (ev.room && pending_take(s->pending_join, ev.room))
            ev.own = 1;   /* our JOIN was refused */
        if (body && body->type == CB_TEXT)
            item_text(body, text_s, sizeof(text_s));
        else
            snprintf(text_s, sizeof(text_s), "(error)");
        ev.text = text_s;
        ev.type = RRC_EV_ERROR;
        s->cb.event(s->ctx, &ev);
        return;

    case RRC_T_PING: {
        uint8_t buf[RNS_LINK_MDU];
        struct cb_writer w;
        cb_writer_init(&w, buf, sizeof(buf));
        if (body)
            put_envelope(s, &w, RRC_T_PONG, NULL, BODY_RAW, body->raw, body->raw_len, 0, NULL);
        else
            put_envelope(s, &w, RRC_T_PONG, NULL, BODY_NONE, NULL, 0, 0, NULL);
        if (!w.overflow && w.len <= s->cb.mdu(s->ctx))
            s->cb.send(s->ctx, buf, w.len);
        return;
    }

    case RRC_T_PONG:
        if (!body || body->type != CB_BYTES || body->len != 8)
            return;
        for (i = 0; i < RRC_PINGS; i++) {
            if (s->pings[i].used && memcmp(s->pings[i].body, body->p, 8) == 0) {
                s->pings[i].used = 0;
                ev.type = RRC_EV_PONG;
                ev.rtt_ms = (now - s->pings[i].at) * 1000.0;
                s->cb.event(s->ctx, &ev);
                return;
            }
        }
        return;

    default:
        return;   /* unknown types must be ignored */
    }
}
