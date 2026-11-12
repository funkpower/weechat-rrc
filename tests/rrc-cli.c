/*
 * rrc-cli.c - a bare RRC client for testing the core against a real hub
 *
 *   rrc-cli <host:port | unix:NAME> <hub-hash> <identity-file> <room> [message...]
 *
 * Connects, links, identifies, joins the room, sends each message, prints
 * every event, and exits a few seconds after the last message.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <stddef.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../src/hdlc.h"
#include "../src/rns.h"
#include "../src/rrc.h"

static int fd = -1;
static struct rns_client client;
static struct rrc_session session;
static struct hdlc_rx rx;
static int done, welcomed, joined;
static double finish_at;

static double
now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int
net_send(void *ctx, const uint8_t *pkt, size_t len)
{
    uint8_t buf[2 * RNS_MTU + 2];
    size_t n = hdlc_frame(pkt, len, buf);
    return write(fd, buf, n) == (ssize_t)n ? 0 : -1;
}

static void
on_state(void *ctx, enum rns_state st, const char *reason)
{
    printf("[link] %s%s%s\n", rns_state_name(st), reason ? ": " : "", reason ? reason : "");
    if (st == RNS_ACTIVE) {
        rns_client_identify(&client, now_s());
        rrc_session_start(&session, client.rtt, now_s());
    } else if (st == RNS_CLOSED) {
        done = 1;
    }
}

static void
on_data(void *ctx, const uint8_t *data, size_t len)
{
    rrc_session_data(&session, data, len, now_s());
}

static void
on_log(void *ctx, int level, const char *msg)
{
    printf("[rns] %s\n", msg);
}

static int
link_send(void *ctx, const uint8_t *data, size_t len)
{
    return rns_client_send(&client, data, len, now_s());
}

static size_t
link_mdu(void *ctx)
{
    return client.mdu;
}

static void
on_event(void *ctx, const struct rrc_event *ev)
{
    char hex[33] = "";
    if (ev->src)
        rns_hex(ev->src, 8, hex);
    switch (ev->type) {
    case RRC_EV_WELCOME:
        printf("[welcome] hub=%s version=%s body_max=%u rate=%u/min\n",
               ev->hub_name ? ev->hub_name : "?", ev->hub_version ? ev->hub_version : "?",
               session.limits.max_msg_body_bytes, session.limits.rate_limit_msgs_per_minute);
        welcomed = 1;
        break;
    case RRC_EV_JOINED:
        printf("[joined] room=%s own=%d members=%zu\n", ev->room, ev->own, ev->n_members);
        if (ev->own)
            joined = 1;
        break;
    case RRC_EV_PARTED:
        printf("[parted] room=%s own=%d\n", ev->room, ev->own);
        break;
    case RRC_EV_MSG:
    case RRC_EV_ACTION:
    case RRC_EV_NOTICE:
        printf("[%s] room=%s src=%s nick=%s own=%d: %s\n",
               ev->type == RRC_EV_MSG ? "msg" : ev->type == RRC_EV_ACTION ? "action" : "notice",
               ev->room ? ev->room : "-", hex, ev->nick ? ev->nick : "-", ev->own, ev->text);
        break;
    case RRC_EV_ERROR:
        printf("[error] room=%s: %s\n", ev->room ? ev->room : "-", ev->text);
        break;
    case RRC_EV_PONG:
        printf("[pong] %.0f ms\n", ev->rtt_ms);
        break;
    case RRC_EV_HELLO_TIMEOUT:
        printf("[hello timeout]\n");
        done = 1;
        break;
    }
}

static void
on_frame(void *ctx, const uint8_t *f, size_t len)
{
    rns_client_inbound(&client, f, len, now_s());
}

static int
connect_to(const char *spec)
{
    if (strncmp(spec, "unix:", 5) == 0) {
        struct sockaddr_un sa;
        size_t n = strlen(spec + 5);
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        /* abstract namespace: "\0rns/<name>", as RNS uses on Linux */
        memcpy(sa.sun_path + 1, "rns/", 4);
        memcpy(sa.sun_path + 5, spec + 5, n);
        if (connect(s, (struct sockaddr *)&sa,
                    (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 5 + n)) != 0)
            return -1;
        return s;
    } else {
        char host[256], *colon;
        struct addrinfo hints, *res, *ai;
        int s = -1;
        snprintf(host, sizeof(host), "%s", spec);
        colon = strrchr(host, ':');
        if (!colon)
            return -1;
        *colon = '\0';
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, colon + 1, &hints, &res) != 0)
            return -1;
        for (ai = res; ai; ai = ai->ai_next) {
            s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s >= 0 && connect(s, ai->ai_addr, ai->ai_addrlen) == 0)
                break;
            if (s >= 0)
                close(s);
            s = -1;
        }
        freeaddrinfo(res);
        return s;
    }
}

int
main(int argc, char **argv)
{
    struct rns_identity id;
    uint8_t hub[RNS_HASH_LEN];
    struct rns_callbacks rcb = { net_send, on_state, on_data, on_log };
    struct rrc_callbacks scb = { link_send, link_mdu, on_event };
    int shared, sent = 0, i, pinged = 0;
    const char *err;
    char hex[33];

    if (argc < 5) {
        fprintf(stderr, "usage: %s <host:port|unix:NAME> <hub-hash> <identity> <room> [msg...]\n", argv[0]);
        return 2;
    }
    if (rns_unhex(argv[2], hub, RNS_HASH_LEN) != 0) {
        fprintf(stderr, "bad hub hash\n");
        return 2;
    }
    if (rns_identity_load(&id, argv[3]) != 0) {
        if (rns_identity_generate(&id) != 0 || rns_identity_save(&id, argv[3]) != 0) {
            perror("identity");
            return 1;
        }
    }
    rns_hex(id.hash, RNS_HASH_LEN, hex);
    printf("identity %s\n", hex);
    shared = strncmp(argv[1], "unix:", 5) == 0;
    fd = connect_to(argv[1]);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    hdlc_rx_init(&rx);
    rns_client_init(&client, &id, hub, shared, &rcb, NULL);
    rrc_session_init(&session, id.hash, "cli-tester", &scb, NULL);
    rns_client_start(&client, now_s());

    while (!done) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        uint8_t buf[4096];
        int r = poll(&pfd, 1, 200);
        double t = now_s();
        if (r > 0) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) {
                printf("[net] connection closed\n");
                break;
            }
            hdlc_rx_feed(&rx, buf, (size_t)n, on_frame, NULL);
        }
        rns_client_tick(&client, t);
        if (client.state == RNS_ACTIVE)
            rrc_session_tick(&session, t);
        if (welcomed && !joined && sent == 0) {
            if (rrc_join(&session, argv[4], t, &err) != 0)
                printf("[join failed] %s\n", err);
            sent = -1;
        }
        if (joined && sent <= 0) {
            for (i = 5; i < argc; i++)
                if (rrc_say(&session, RRC_T_MSG, argv[4], argv[i], t, &err) != 0)
                    printf("[say failed] %s\n", err);
            if (!pinged && rrc_ping(&session, t, &err) == 0)
                pinged = 1;
            sent = 1;
            finish_at = t + 4.0;
        }
        if (sent == 1 && t >= finish_at) {
            rns_client_close(&client, t, "done");
        }
    }
    rrc_session_free(&session);
    close(fd);
    return 0;
}
