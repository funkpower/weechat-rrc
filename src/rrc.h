/*
 * rrc.h - Reticulum Relay Chat session (RRC spec 0.1.3, rrcd 0.3)
 *
 * Encodes and decodes RRC envelopes and keeps the per-link session state:
 * HELLO/WELCOME, the hub's limits, a client-side rate limit, and the ids of
 * our own messages so the hub's echo of them can be recognised. It does not
 * own the link: it hands encoded envelopes to a send callback.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_RRC_H
#define RRC_RRC_H

#include <stddef.h>
#include <stdint.h>

#include "rns.h"

#define RRC_VERSION 1

#define RRC_T_HELLO 1
#define RRC_T_WELCOME 2
#define RRC_T_JOIN 10
#define RRC_T_JOINED 11
#define RRC_T_PART 12
#define RRC_T_PARTED 13
#define RRC_T_MSG 20
#define RRC_T_NOTICE 21
#define RRC_T_ACTION 22
#define RRC_T_PING 30
#define RRC_T_PONG 31
#define RRC_T_ERROR 40
#define RRC_T_RESOURCE_ENVELOPE 50

#define RRC_K_V 0
#define RRC_K_T 1
#define RRC_K_ID 2
#define RRC_K_TS 3
#define RRC_K_SRC 4
#define RRC_K_ROOM 5
#define RRC_K_BODY 6
#define RRC_K_NICK 7
#define RRC_K_DST 8   /* rrcd extension: direct NOTICE to one identity */

#define RRC_MAX_NICK 64
#define RRC_MAX_ROOM 128
#define RRC_MAX_TEXT 1024
#define RRC_MAX_MEMBERS 64

struct rrc_limits {
    unsigned max_nick_bytes;
    unsigned max_room_name_bytes;
    unsigned max_msg_body_bytes;
    unsigned max_rooms_per_session;
    unsigned rate_limit_msgs_per_minute;
};

enum rrc_event_type {
    RRC_EV_WELCOME,
    RRC_EV_JOINED,
    RRC_EV_PARTED,
    RRC_EV_MSG,
    RRC_EV_NOTICE,
    RRC_EV_ACTION,
    RRC_EV_ERROR,
    RRC_EV_PONG,
    RRC_EV_HELLO_TIMEOUT,
    RRC_EV_DIRECT,          /* a NOTICE addressed to us alone (rrcd K_DST) */
};

/* Every string is NUL-terminated, valid UTF-8, and free of control
 * characters; NULL when the hub sent none. */
struct rrc_event {
    enum rrc_event_type type;
    const char *room;           /* normalised: trimmed, lower case */
    const uint8_t *src;         /* RNS_HASH_LEN bytes, or NULL */
    const char *nick;
    const char *text;
    const uint8_t (*members)[RNS_HASH_LEN];
    size_t n_members;
    int own;                    /* about us: our JOINED/PARTED, our echo */
    uint64_t ts;
    double rtt_ms;              /* PONG */
    const char *hub_name;       /* WELCOME */
    const char *hub_version;
};

struct rrc_callbacks {
    /* Send one encoded envelope on the link. Returns 0 on success. */
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    /* Current link MDU (largest envelope that fits one packet). */
    size_t (*mdu)(void *ctx);
    void (*event)(void *ctx, const struct rrc_event *ev);
};

struct rrc_queued {
    struct rrc_queued *next;
    size_t len;
    uint8_t data[RNS_LINK_MDU];
};

#define RRC_SENT_IDS 128
#define RRC_PINGS 8
#define RRC_RES_EXPECT 8

/* A RESOURCE_ENVELOPE: a resource the hub is about to send (rrc_resource.c) */
struct rrc_res_expect {
    int used;
    int kind;                   /* 1 notice, 2 motd, 0 anything else */
    size_t size;
    int has_sha256;
    uint8_t sha256[32];
    int has_src;
    uint8_t src[RNS_HASH_LEN];
    char room[RRC_MAX_ROOM];
    double expires;
};

struct rrc_session {
    struct rrc_callbacks cb;
    void *ctx;
    uint8_t self[RNS_HASH_LEN];
    char nick[RRC_MAX_NICK];

    int welcomed;
    int hello_tries;
    double hello_sent;
    double hello_interval;
    char hub_name[RRC_MAX_NICK];
    int hub_direct;             /* the hub forwards direct NOTICEs */
    struct rrc_limits limits;

    uint8_t sent_ids[RRC_SENT_IDS][8];
    size_t sent_next;

    struct { uint8_t body[8]; double at; int used; } pings[RRC_PINGS];

    /* rooms we asked to join or leave, to recognise the hub's reply: rrcd
     * sends the same bodiless JOINED to us and, about us, to everyone else */
    char pending_join[16][RRC_MAX_ROOM];
    char pending_part[16][RRC_MAX_ROOM];

    double tokens;
    double refill_at;
    struct rrc_queued *queue_head, *queue_tail;
    size_t queued;

    struct rrc_res_expect res_expect[RRC_RES_EXPECT];
};

void rrc_session_init(struct rrc_session *s, const uint8_t self[RNS_HASH_LEN],
                      const char *nick, const struct rrc_callbacks *cb, void *ctx);
void rrc_session_free(struct rrc_session *s);

/* The link is up and identified: send HELLO. rtt in seconds. */
void rrc_session_start(struct rrc_session *s, double rtt, double now);
void rrc_session_data(struct rrc_session *s, const uint8_t *data, size_t len, double now);
void rrc_session_tick(struct rrc_session *s, double now);
/* A resource the link received: delivered as the NOTICE its envelope
 * announced, or dropped if none did. */
void rrc_session_resource(struct rrc_session *s, const uint8_t *data, size_t len, double now);
/* internal: a RESOURCE_ENVELOPE's body (rrc_resource.c) */
struct cb_item;
void rrc_res_envelope(struct rrc_session *s, const struct rrc_event *ev,
                      const struct cb_item *body, double now);

/* These queue an envelope; returns 0, or -1 with a reason in *err. */
int rrc_join(struct rrc_session *s, const char *room, double now, const char **err);
int rrc_part(struct rrc_session *s, const char *room, double now, const char **err);
/* type: RRC_T_MSG, RRC_T_ACTION or RRC_T_NOTICE. room may be NULL for a
 * hub command ("/who"). */
int rrc_say(struct rrc_session *s, int type, const char *room, const char *text,
            double now, const char **err);
int rrc_ping(struct rrc_session *s, double now, const char **err);
/* A NOTICE to one identity (full hash), on hubs that offer it. */
int rrc_direct(struct rrc_session *s, const uint8_t dst[RNS_HASH_LEN], const char *text,
               double now, const char **err);
/* Largest body of a direct message. */
size_t rrc_max_direct(struct rrc_session *s);
void rrc_set_nick(struct rrc_session *s, const char *nick);

/* Largest body (in bytes) a message to this room can carry right now. */
size_t rrc_max_body(struct rrc_session *s, const char *room);

/* Normalise a room name as rrcd does: trim, ASCII lower case. Returns the
 * length, or 0 if empty or too long for out. */
size_t rrc_normalize_room(const char *in, char *out, size_t out_size);

/* Copy untrusted text into out as valid UTF-8 without control characters. */
void rrc_clean_text(const uint8_t *in, size_t len, char *out, size_t out_size);

#endif
