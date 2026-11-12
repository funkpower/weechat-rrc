/*
 * plugin.c - WeeChat glue for Reticulum Relay Chat
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <weechat-plugin.h>

#include "crypto.h"
#include "hdlc.h"
#include "micron.h"
#include "rns.h"
#include "rrc.h"

WEECHAT_PLUGIN_NAME("rrc");
WEECHAT_PLUGIN_DESCRIPTION("Reticulum Relay Chat (RRC)");
WEECHAT_PLUGIN_AUTHOR("funkpower");
WEECHAT_PLUGIN_VERSION(RRC_CLIENT_VERSION);
WEECHAT_PLUGIN_LICENSE("GPL3");

struct t_weechat_plugin *weechat_rrc_plugin = NULL;
#define weechat_plugin weechat_rrc_plugin

#define RRC_CONFIG_NAME "rrc"
#define OUTBUF_MAX (1024 * 1024)
#define RECONNECT_MIN 10
#define RECONNECT_MAX 300
#define HEX_SHORT 8

/* ---- data ---- */

struct rrc_member {
    uint8_t hash[RNS_HASH_LEN];
    size_t hash_len;            /* 16, or 6 when only a /who prefix is known */
    char nick[RRC_MAX_NICK];
    char shown[RRC_MAX_NICK];   /* name currently in the nicklist */
    struct rrc_member *next;
};

struct rrc_server;

struct rrc_room {
    struct rrc_server *server;
    char name[RRC_MAX_ROOM];
    struct t_gui_buffer *buffer;
    int joined;
    int who_pending;
    struct rrc_member *members;
    struct rrc_room *next;
};

enum conn_state { CONN_IDLE, CONN_CONNECTING, CONN_UP };

struct rrc_server {
    char name[64];
    struct t_gui_buffer *buffer;
    enum conn_state conn;
    int fd;
    int shared;
    struct t_hook *hook_connect;
    struct t_hook *hook_read;
    struct t_hook *hook_write;
    struct hdlc_rx rx;
    uint8_t *out;
    size_t out_len, out_cap;

    struct rns_client *link;
    struct rrc_session session;
    int session_live;
    int welcomed;
    char hub_name[RRC_MAX_NICK];
    uint8_t hub_identity[RNS_HASH_LEN];   /* who the hub's own notices come from */

    int close_pending;          /* the link closed inside a callback */
    char close_reason[160];
    int user_disconnect;
    double reconnect_at;
    int reconnect_delay;

    struct rrc_room *rooms;
    struct rrc_server *next;
};

static struct rrc_server *servers = NULL;
static struct rns_identity identity;
static int identity_loaded = 0;
static struct t_hook *timer_hook = NULL;

static struct t_config_file *config_file = NULL;
static struct t_config_section *section_network = NULL;
static struct t_config_section *section_server = NULL;
static struct t_config_option *opt_identity_file = NULL;
static struct t_config_option *opt_path_timeout = NULL;
static struct t_config_option *opt_debug = NULL;
static struct t_config_option *opt_render_micron = NULL;

static const char *SERVER_KEYS[] = { "hub", "address", "nick", "autojoin", "autoconnect", NULL };

static double
now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- config ---- */

static struct t_config_option *
server_option(const char *server, const char *key)
{
    char name[128];

    snprintf(name, sizeof(name), "%s.%s", server, key);
    return weechat_config_search_option(config_file, section_server, name);
}

static const char *
server_value(const char *server, const char *key)
{
    struct t_config_option *o = server_option(server, key);
    const char *v = o ? weechat_config_string(o) : NULL;

    return v ? v : "";
}

static int
server_bool(const char *server, const char *key)
{
    const char *v = server_value(server, key);

    return strcmp(v, "on") == 0 || strcmp(v, "true") == 0 || strcmp(v, "1") == 0;
}

static int
known_key(const char *key)
{
    int i;

    for (i = 0; SERVER_KEYS[i]; i++)
        if (strcmp(SERVER_KEYS[i], key) == 0)
            return 1;
    return 0;
}

static int
create_server_option_cb(const void *pointer, void *data, struct t_config_file *file,
                        struct t_config_section *section, const char *option_name,
                        const char *value)
{
    const char *dot = strrchr(option_name, '.');
    struct t_config_option *o;

    if (!dot || dot == option_name || !known_key(dot + 1))
        return WEECHAT_CONFIG_OPTION_SET_ERROR;
    o = weechat_config_search_option(file, section, option_name);
    if (o)
        return weechat_config_option_set(o, value, 1);
    o = weechat_config_new_option(file, section, option_name, "string",
                                  "RRC server option", NULL, 0, 0, "", value, 0,
                                  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return o ? WEECHAT_CONFIG_OPTION_SET_OK_CHANGED : WEECHAT_CONFIG_OPTION_SET_ERROR;
}

static int
set_server_option(const char *server, const char *key, const char *value)
{
    char name[128];

    snprintf(name, sizeof(name), "%s.%s", server, key);
    return create_server_option_cb(NULL, NULL, config_file, section_server, name, value);
}

static int
config_init(void)
{
    config_file = weechat_config_new(RRC_CONFIG_NAME, NULL, NULL, NULL);
    if (!config_file)
        return -1;
    section_network = weechat_config_new_section(config_file, "network", 0, 0,
                                                 NULL, NULL, NULL, NULL, NULL, NULL,
                                                 NULL, NULL, NULL, NULL, NULL, NULL,
                                                 NULL, NULL, NULL);
    opt_identity_file = weechat_config_new_option(
        config_file, section_network, "identity_file", "string",
        "Reticulum identity file (64 private key bytes, as RNS writes them; created "
        "if missing; path is evaluated, see /help eval)",
        NULL, 0, 0, "${weechat_data_dir}/rrc/identity", NULL, 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    opt_path_timeout = weechat_config_new_option(
        config_file, section_network, "path_timeout", "integer",
        "seconds to wait for a path to the hub before giving up",
        NULL, 10, 3600, "90", NULL, 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    opt_debug = weechat_config_new_option(
        config_file, section_network, "debug", "boolean",
        "show Reticulum details (paths, links) in the server buffer",
        NULL, 0, 0, "off", NULL, 0,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    {
        struct t_config_section *look = weechat_config_new_section(
            config_file, "look", 0, 0, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        opt_render_micron = weechat_config_new_option(
            config_file, look, "render_micron", "boolean",
            "show Micron formatting in messages (colours, bold...) as NomadNet does; "
            "off shows the raw tags",
            NULL, 0, 0, "on", NULL, 0,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    section_server = weechat_config_new_section(config_file, "server", 1, 1,
                                                NULL, NULL, NULL, NULL, NULL, NULL,
                                                NULL, NULL, NULL,
                                                &create_server_option_cb, NULL, NULL,
                                                NULL, NULL, NULL);
    return section_server ? 0 : -1;
}

/* ---- identity ---- */

static int
identity_ensure(struct t_gui_buffer *buffer)
{
    char *path, *slash, hex[2 * RNS_HASH_LEN + 1];

    if (identity_loaded)
        return 0;
    path = weechat_string_eval_path_home(weechat_config_string(opt_identity_file),
                                         NULL, NULL, NULL);
    if (!path)
        return -1;
    if (rns_identity_load(&identity, path) != 0) {
        if (errno != ENOENT) {
            weechat_printf(buffer, "%srrc: cannot read identity %s: %s",
                           weechat_prefix("error"), path, strerror(errno));
            free(path);
            return -1;
        }
        slash = strrchr(path, '/');
        if (slash) {
            *slash = '\0';
            weechat_mkdir_parents(path, 0700);
            *slash = '/';
        }
        if (rns_identity_generate(&identity) != 0 || rns_identity_save(&identity, path) != 0) {
            weechat_printf(buffer, "%srrc: cannot create identity %s: %s",
                           weechat_prefix("error"), path, strerror(errno));
            free(path);
            return -1;
        }
        rns_hex(identity.hash, RNS_HASH_LEN, hex);
        weechat_printf(buffer, "rrc: created identity %s in %s", hex, path);
    }
    free(path);
    identity_loaded = 1;
    return 0;
}

/* ---- lookups ---- */

static struct rrc_server *
server_find(const char *name)
{
    struct rrc_server *s;

    for (s = servers; s; s = s->next)
        if (strcmp(s->name, name) == 0)
            return s;
    return NULL;
}

static struct rrc_room *
room_find(struct rrc_server *s, const char *name)
{
    struct rrc_room *r;

    for (r = s->rooms; r; r = r->next)
        if (strcmp(r->name, name) == 0)
            return r;
    return NULL;
}

/* The server and room behind a buffer (room may be NULL). */
static struct rrc_server *
buffer_context(struct t_gui_buffer *buffer, struct rrc_room **room_out)
{
    struct rrc_server *s;
    struct rrc_room *r;

    if (room_out)
        *room_out = NULL;
    for (s = servers; s; s = s->next) {
        if (s->buffer == buffer)
            return s;
        for (r = s->rooms; r; r = r->next) {
            if (r->buffer == buffer) {
                if (room_out)
                    *room_out = r;
                return s;
            }
        }
    }
    return NULL;
}

/* ---- display ---- */

static void
short_hash(const uint8_t *hash, size_t len, char *out)
{
    rns_hex(hash, len > HEX_SHORT / 2 ? HEX_SHORT / 2 : len, out);
}

/* A name made safe for a WeeChat tag: no commas or spaces. */
static void
tag_safe(const char *in, char *out, size_t size)
{
    size_t i;

    snprintf(out, size, "%s", in);
    for (i = 0; out[i]; i++)
        if (out[i] == ',' || out[i] == ' ' || out[i] == '\t')
            out[i] = '_';
}

static char *
nick_color(const char *nick)
{
    return weechat_info_get("nick_color", nick);
}

static struct t_gui_buffer *
server_buffer(struct rrc_server *s)
{
    return s->buffer ? s->buffer : NULL;
}

static const char *
wcolor(const char *name)
{
    return weechat_color(name);
}

/* Print text line by line, with Micron formatting rendered when enabled. */
static void
print_lines(struct t_gui_buffer *buffer, const char *tags, const char *prefix,
            const char *text)
{
    static char line[RRC_MAX_TEXT], shown[8 * RRC_MAX_TEXT];
    const char *p = text, *nl;
    size_t n;

    do {
        nl = strchr(p, '\n');
        n = nl ? (size_t)(nl - p) : strlen(p);
        if (n >= sizeof(line))
            n = sizeof(line) - 1;
        memcpy(line, p, n);
        line[n] = '\0';
        if (opt_render_micron && weechat_config_boolean(opt_render_micron) && micron_present(line))
            micron_render(line, shown, sizeof(shown), &wcolor);
        else
            snprintf(shown, sizeof(shown), "%s", line);
        weechat_printf_date_tags(buffer, 0, tags, "%s%s", prefix, shown);
        p = nl ? nl + 1 : NULL;
    } while (p && *p);
}

static void
server_print(struct rrc_server *s, const char *prefix_name, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    weechat_printf(server_buffer(s), "%s%s",
                   prefix_name ? weechat_prefix(prefix_name) : "", buf);
}

/* ---- members and nicklist ---- */

static void
member_display(const struct rrc_member *m, char *out, size_t size)
{
    char hex[HEX_SHORT + 1];

    if (m->nick[0]) {
        snprintf(out, size, "%s", m->nick);
    } else {
        short_hash(m->hash, m->hash_len, hex);
        snprintf(out, size, "%s", hex);
    }
}

static void
nicklist_sync(struct rrc_room *r, struct rrc_member *m)
{
    char name[RRC_MAX_NICK];
    struct t_gui_nick *n;
    char *color;

    if (!r->buffer)
        return;
    member_display(m, name, sizeof(name));
    if (m->shown[0] && strcmp(m->shown, name) != 0) {
        n = weechat_nicklist_search_nick(r->buffer, NULL, m->shown);
        if (n)
            weechat_nicklist_remove_nick(r->buffer, n);
        m->shown[0] = '\0';
    }
    if (!weechat_nicklist_search_nick(r->buffer, NULL, name)) {
        color = nick_color(name);
        weechat_nicklist_add_nick(r->buffer, NULL, name, color ? color : "default",
                                  "", "lightgreen", 1);
        free(color);
    }
    snprintf(m->shown, sizeof(m->shown), "%s", name);
}

static int
hash_matches(const struct rrc_member *m, const uint8_t *hash, size_t len)
{
    size_t n = m->hash_len < len ? m->hash_len : len;

    return n > 0 && memcmp(m->hash, hash, n) == 0;
}

static struct rrc_member *
member_find(struct rrc_room *r, const uint8_t *hash, size_t len, const char *nick)
{
    struct rrc_member *m;

    for (m = r->members; m; m = m->next) {
        if (hash && hash_matches(m, hash, len))
            return m;
        if (!hash && nick && strcmp(m->nick, nick) == 0)
            return m;
    }
    return NULL;
}

static struct rrc_member *
member_upsert(struct rrc_room *r, const uint8_t *hash, size_t len, const char *nick)
{
    struct rrc_member *m = member_find(r, hash, len, nick);

    if (!m) {
        if (!hash && !nick)
            return NULL;
        m = calloc(1, sizeof(*m));
        if (!m)
            return NULL;
        m->next = r->members;
        r->members = m;
    }
    if (hash && len >= m->hash_len) {
        memcpy(m->hash, hash, len);
        m->hash_len = len;
    }
    if (nick && nick[0])
        snprintf(m->nick, sizeof(m->nick), "%s", nick);
    nicklist_sync(r, m);
    return m;
}

static void
member_remove(struct rrc_room *r, const uint8_t *hash, size_t len, const char *nick)
{
    struct rrc_member **pp, *m;
    struct t_gui_nick *n;

    for (pp = &r->members; (m = *pp); pp = &m->next) {
        if ((hash && hash_matches(m, hash, len)) || (!hash && nick && strcmp(m->nick, nick) == 0)) {
            *pp = m->next;
            if (r->buffer && m->shown[0]) {
                n = weechat_nicklist_search_nick(r->buffer, NULL, m->shown);
                if (n)
                    weechat_nicklist_remove_nick(r->buffer, n);
            }
            free(m);
            return;
        }
    }
}

static void
members_clear(struct rrc_room *r)
{
    struct rrc_member *m, *next;

    for (m = r->members; m; m = next) {
        next = m->next;
        free(m);
    }
    r->members = NULL;
    if (r->buffer)
        weechat_nicklist_remove_all(r->buffer);
}

/* Display name for a sender: their nick, else the start of their hash. */
static void
sender_name(struct rrc_room *r, const struct rrc_event *ev, char *out, size_t size)
{
    struct rrc_member *m = NULL;
    char hex[HEX_SHORT + 1];

    if (ev->nick) {
        snprintf(out, size, "%s", ev->nick);
        return;
    }
    if (r && ev->src)
        m = member_find(r, ev->src, RNS_HASH_LEN, NULL);
    if (m) {
        member_display(m, out, size);
        return;
    }
    if (ev->src) {
        short_hash(ev->src, RNS_HASH_LEN, hex);
        snprintf(out, size, "%s", hex);
    } else {
        snprintf(out, size, "?");
    }
}

/* ---- buffers ---- */

static int room_input_cb(const void *pointer, void *data, struct t_gui_buffer *buffer,
                         const char *input);
static int room_close_cb(const void *pointer, void *data, struct t_gui_buffer *buffer);
static int server_input_cb(const void *pointer, void *data, struct t_gui_buffer *buffer,
                           const char *input);
static int server_close_cb(const void *pointer, void *data, struct t_gui_buffer *buffer);
static void server_disconnect(struct rrc_server *s, const char *reason, int reconnect);

static void
set_nick_localvar(struct rrc_server *s)
{
    struct rrc_room *r;
    const char *nick = s->session.nick[0] ? s->session.nick : server_value(s->name, "nick");

    if (s->buffer)
        weechat_buffer_set(s->buffer, "localvar_set_nick", nick);
    for (r = s->rooms; r; r = r->next) {
        if (!r->buffer)
            continue;
        weechat_buffer_set(r->buffer, "localvar_set_nick", nick);
        weechat_buffer_set(r->buffer, "highlight_words", nick);
    }
}

static void
server_buffer_open(struct rrc_server *s)
{
    char name[128];

    if (s->buffer)
        return;
    snprintf(name, sizeof(name), "server.%s", s->name);
    s->buffer = weechat_buffer_search(RRC_CONFIG_NAME, name);
    if (s->buffer) {
        /* a buffer kept by /upgrade has no callbacks: without them its input
         * is refused and closing it would leave a dangling pointer here */
        weechat_buffer_set_pointer(s->buffer, "input_callback", &server_input_cb);
        weechat_buffer_set_pointer(s->buffer, "close_callback", &server_close_cb);
    } else {
        s->buffer = weechat_buffer_new(name, &server_input_cb, NULL, NULL,
                                       &server_close_cb, NULL, NULL);
    }
    if (!s->buffer)
        return;
    weechat_buffer_set(s->buffer, "short_name", s->name);
    weechat_buffer_set(s->buffer, "localvar_set_type", "server");
    weechat_buffer_set(s->buffer, "localvar_set_server", s->name);
    weechat_buffer_set(s->buffer, "localvar_set_channel", s->name);
    weechat_buffer_set(s->buffer, "title", "Reticulum Relay Chat");
    set_nick_localvar(s);
}

static struct rrc_room *
room_open(struct rrc_server *s, const char *room, int switch_to)
{
    struct rrc_room *r = room_find(s, room);
    char name[256];

    if (!r) {
        r = calloc(1, sizeof(*r));
        if (!r)
            return NULL;
        r->server = s;
        snprintf(r->name, sizeof(r->name), "%s", room);
        r->next = s->rooms;
        s->rooms = r;
    }
    if (!r->buffer) {
        snprintf(name, sizeof(name), "%s.%s", s->name, room);
        r->buffer = weechat_buffer_search(RRC_CONFIG_NAME, name);
        if (r->buffer) {
            weechat_buffer_set_pointer(r->buffer, "input_callback", &room_input_cb);
            weechat_buffer_set_pointer(r->buffer, "close_callback", &room_close_cb);
        } else {
            r->buffer = weechat_buffer_new(name, &room_input_cb, NULL, NULL,
                                           &room_close_cb, NULL, NULL);
        }
        if (!r->buffer)
            return r;
        weechat_buffer_set(r->buffer, "short_name", room);
        weechat_buffer_set(r->buffer, "localvar_set_type", "channel");
        weechat_buffer_set(r->buffer, "localvar_set_server", s->name);
        weechat_buffer_set(r->buffer, "localvar_set_channel", room);
        weechat_buffer_set(r->buffer, "nicklist", "1");
        weechat_buffer_set(r->buffer, "nicklist_display_groups", "0");
        set_nick_localvar(s);
    }
    if (switch_to)
        weechat_buffer_set(r->buffer, "display", "1");
    return r;
}

static void
room_free(struct rrc_server *s, struct rrc_room *r)
{
    struct rrc_room **pp;

    for (pp = &s->rooms; *pp; pp = &(*pp)->next) {
        if (*pp == r) {
            *pp = r->next;
            break;
        }
    }
    members_clear(r);
    free(r);
}

/* ---- socket I/O ---- */

static int
write_cb(const void *pointer, void *data, int fd);

static void
flush_out(struct rrc_server *s)
{
    ssize_t n;

    while (s->out_len > 0) {
        n = write(s->fd, s->out, s->out_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            s->close_pending = 1;
            snprintf(s->close_reason, sizeof(s->close_reason), "write error: %s",
                     strerror(errno));
            s->out_len = 0;
            return;
        }
        memmove(s->out, s->out + n, s->out_len - (size_t)n);
        s->out_len -= (size_t)n;
    }
    if (s->out_len > 0 && !s->hook_write)
        s->hook_write = weechat_hook_fd(s->fd, 0, 1, 0, &write_cb, s, NULL);
    else if (s->out_len == 0 && s->hook_write) {
        weechat_unhook(s->hook_write);
        s->hook_write = NULL;
    }
}

static int
write_cb(const void *pointer, void *data, int fd)
{
    flush_out((struct rrc_server *)pointer);
    return WEECHAT_RC_OK;
}

static int
net_send_cb(void *ctx, const uint8_t *pkt, size_t len)
{
    struct rrc_server *s = ctx;
    size_t need = 2 * len + 2;
    uint8_t *grown;

    if (s->conn != CONN_UP || s->fd < 0)
        return -1;
    if (s->out_len + need > OUTBUF_MAX) {
        s->close_pending = 1;
        snprintf(s->close_reason, sizeof(s->close_reason), "send buffer overflow");
        return -1;
    }
    if (s->out_len + need > s->out_cap) {
        size_t cap = s->out_cap ? s->out_cap : 4096;
        while (cap < s->out_len + need)
            cap *= 2;
        grown = realloc(s->out, cap);
        if (!grown)
            return -1;
        s->out = grown;
        s->out_cap = cap;
    }
    s->out_len += hdlc_frame(pkt, len, s->out + s->out_len);
    flush_out(s);
    return 0;
}

/* ---- link callbacks ---- */

static void
link_log_cb(void *ctx, int level, const char *msg)
{
    struct rrc_server *s = ctx;

    if (level == RNS_LOG_DEBUG && !weechat_config_boolean(opt_debug))
        return;
    server_print(s, level == RNS_LOG_ERROR ? "error" : "network", "%s", msg);
}

static int
session_send_cb(void *ctx, const uint8_t *data, size_t len)
{
    struct rrc_server *s = ctx;

    return s->link ? rns_client_send(s->link, data, len, now_s()) : -1;
}

static size_t
session_mdu_cb(void *ctx)
{
    struct rrc_server *s = ctx;

    return s->link ? s->link->mdu : RNS_LINK_MDU;
}

static void
link_state_cb(void *ctx, enum rns_state state, const char *reason)
{
    struct rrc_server *s = ctx;
    double now = now_s();

    switch (state) {
    case RNS_LINKING:
        server_print(s, "network", "path to the hub found (%d hop%s), opening a link",
                     s->link->hops, s->link->hops == 1 ? "" : "s");
        break;
    case RNS_ACTIVE: {
        uint8_t full[32];
        cr_sha256(s->link->dest_pub, RNS_PUBKEY_LEN, full);
        memcpy(s->hub_identity, full, RNS_HASH_LEN);
        server_print(s, "network", "link established (round trip %.0f ms)",
                     s->link->rtt * 1000.0);
        rns_client_identify(s->link, now);
        rrc_session_start(&s->session, s->link->rtt, now);
        s->session_live = 1;
        break;
    }
    case RNS_CLOSED:
        s->close_pending = 1;
        snprintf(s->close_reason, sizeof(s->close_reason), "%s",
                 reason ? reason : "link closed");
        break;
    default:
        break;
    }
}

static void
link_data_cb(void *ctx, const uint8_t *data, size_t len)
{
    struct rrc_server *s = ctx;

    if (s->session_live)
        rrc_session_data(&s->session, data, len, now_s());
}

/* ---- RRC events ---- */

static void
join_rooms(struct rrc_server *s)
{
    const char *autojoin = server_value(s->name, "autojoin");
    struct rrc_room *r;
    const char *err;
    char **list;
    int i, n = 0;

    /* rooms already open (a reconnect), then the autojoin list */
    for (r = s->rooms; r; r = r->next)
        if (r->buffer && rrc_join(&s->session, r->name, now_s(), &err) != 0)
            server_print(s, "error", "cannot join %s: %s", r->name, err);
    list = weechat_string_split(autojoin, ",", NULL,
                                WEECHAT_STRING_SPLIT_STRIP_LEFT
                                | WEECHAT_STRING_SPLIT_STRIP_RIGHT
                                | WEECHAT_STRING_SPLIT_COLLAPSE_SEPS, 0, &n);
    for (i = 0; list && i < n; i++) {
        char norm[RRC_MAX_ROOM];
        if (!rrc_normalize_room(list[i], norm, sizeof(norm)) || room_find(s, norm))
            continue;
        room_open(s, norm, 0);
        if (rrc_join(&s->session, norm, now_s(), &err) != 0)
            server_print(s, "error", "cannot join %s: %s", norm, err);
    }
    weechat_string_free_split(list);
}

static void
room_set_topic(struct rrc_room *r, const char *topic, size_t len)
{
    char title[RRC_MAX_TEXT];

    if (!r->buffer)
        return;
    if (len >= sizeof(title))
        len = sizeof(title) - 1;
    memcpy(title, topic, len);
    title[len] = '\0';
    if (strcmp(title, "(none)") == 0 || strcmp(title, "(cleared)") == 0)
        title[0] = '\0';
    weechat_buffer_set(r->buffer, "title", title);
}

/* Room name between prefix and ": " (or " is now: "), as rrcd writes it. */
static struct rrc_room *
notice_room(struct rrc_server *s, const char *text, const char *prefix, const char *sep,
            const char **rest)
{
    char room[RRC_MAX_ROOM];
    const char *end;
    size_t n;

    if (strncmp(text, prefix, strlen(prefix)) != 0)
        return NULL;
    end = strstr(text + strlen(prefix), sep);
    if (!end)
        return NULL;
    n = (size_t)(end - text) - strlen(prefix);
    if (n == 0 || n >= sizeof(room))
        return NULL;
    memcpy(room, text + strlen(prefix), n);
    room[n] = '\0';
    *rest = end + strlen(sep);
    return room_find(s, room);
}

/* The topic, from the notices rrcd sends:
 *   "room lobby: unregistered; mode=(none); topic=(none)"   (on join)
 *   "room x: registered; topic=Some topic; modes=+r"         (other hubs)
 *   "topic for lobby: Some topic"                            (/topic lobby)
 *   "topic for lobby is now: Some topic"                     (a change) */
static void
handle_topic_notice(struct rrc_server *s, const char *text)
{
    struct rrc_room *r;
    const char *rest, *topic, *end, *cut;

    if (strchr(text, '\n'))
        return;
    if ((r = notice_room(s, text, "topic for ", " is now: ", &rest))
        || (r = notice_room(s, text, "topic for ", ": ", &rest))) {
        room_set_topic(r, rest, strlen(rest));
        return;
    }
    if ((r = notice_room(s, text, "room ", ": ", &rest))) {
        topic = strstr(rest, "topic=");
        if (!topic)
            return;
        topic += 6;
        end = topic + strlen(topic);
        /* the field ends at a following "; mode" field, if any */
        cut = strstr(topic, "; mode");
        if (cut)
            end = cut;
        room_set_topic(r, topic, (size_t)(end - topic));
    }
}

/* "members in lobby: nick (0123456789ab), nick2 (...), 0123...ef" */
static int
handle_who_notice(struct rrc_server *s, const char *text)
{
    const char *prefix = "members in ";
    char room[RRC_MAX_ROOM], copy[RRC_MAX_TEXT], *entry, *save = NULL;
    const char *colon;
    struct rrc_room *r;
    size_t n;

    if (strncmp(text, prefix, strlen(prefix)) != 0)
        return 0;
    colon = strstr(text, ": ");
    if (!colon)
        return 0;
    n = (size_t)(colon - text) - strlen(prefix);
    if (n == 0 || n >= sizeof(room))
        return 0;
    memcpy(room, text + strlen(prefix), n);
    room[n] = '\0';
    r = room_find(s, room);
    if (!r || !r->who_pending)
        return 0;
    r->who_pending = 0;
    snprintf(copy, sizeof(copy), "%s", colon + 2);
    if (strcmp(copy, "(none)") == 0)
        return 1;
    for (entry = strtok_r(copy, ",", &save); entry; entry = strtok_r(NULL, ",", &save)) {
        uint8_t hash[RNS_HASH_LEN];
        char *open, *close;
        while (*entry == ' ')
            entry++;
        open = strrchr(entry, '(');
        close = open ? strchr(open, ')') : NULL;
        if (open && close && close - open - 1 == 12) {
            *close = '\0';
            if (rns_unhex(open + 1, hash, 6) != 0)
                continue;
            while (open > entry && open[-1] == ' ')
                open--;
            *open = '\0';
            member_upsert(r, hash, 6, entry);
        } else if (strlen(entry) == 2 * RNS_HASH_LEN && rns_unhex(entry, hash, RNS_HASH_LEN) == 0) {
            member_upsert(r, hash, RNS_HASH_LEN, NULL);
        }
    }
    return 1;
}

static void
print_message(struct rrc_server *s, struct rrc_room *r, const struct rrc_event *ev)
{
    char name[RRC_MAX_NICK], tagnick[RRC_MAX_NICK], tags[256], prefix[256];
    char *color;

    sender_name(r, ev, name, sizeof(name));
    tag_safe(name, tagnick, sizeof(tagnick));
    if (r && ev->src)
        member_upsert(r, ev->src, RNS_HASH_LEN, ev->nick);
    color = nick_color(name);
    if (ev->type == RRC_EV_ACTION) {
        snprintf(tags, sizeof(tags), "rrc_action,notify_message,nick_%s,log1", tagnick);
        snprintf(prefix, sizeof(prefix), "%s%s%s%s ", weechat_prefix("action"),
                 color ? color : "", name, weechat_color("reset"));
    } else {
        snprintf(tags, sizeof(tags), "rrc_msg,notify_message,nick_%s,log1", tagnick);
        snprintf(prefix, sizeof(prefix), "%s%s%s\t", color ? color : "", name,
                 weechat_color("reset"));
    }
    free(color);
    print_lines(r ? r->buffer : s->buffer, tags, prefix, ev->text);
}

static void
session_event_cb(void *ctx, const struct rrc_event *ev)
{
    struct rrc_server *s = ctx;
    struct rrc_room *r = ev->room ? room_find(s, ev->room) : NULL;
    char name[RRC_MAX_NICK], prefix[256];
    size_t i;

    switch (ev->type) {
    case RRC_EV_WELCOME:
        s->welcomed = 1;
        s->reconnect_delay = 0;
        snprintf(s->hub_name, sizeof(s->hub_name), "%s", ev->hub_name ? ev->hub_name : "");
        server_print(s, "network", "connected to hub %s%s%s%s", ev->hub_name ? ev->hub_name : "?",
                     ev->hub_version ? " (rrcd " : "", ev->hub_version ? ev->hub_version : "",
                     ev->hub_version ? ")" : "");
        if (s->buffer)
            weechat_buffer_set(s->buffer, "title", ev->hub_name ? ev->hub_name : "");
        set_nick_localvar(s);
        join_rooms(s);
        break;

    case RRC_EV_JOINED:
        if (ev->own) {
            const char *err;
            r = room_open(s, ev->room, 0);
            if (!r)
                break;
            r->joined = 1;
            members_clear(r);
            member_upsert(r, s->session.self, RNS_HASH_LEN, s->session.nick);
            for (i = 0; i < ev->n_members; i++)
                member_upsert(r, ev->members[i], RNS_HASH_LEN, NULL);
            weechat_printf_date_tags(r->buffer, 0, "rrc_join,log4", "%syou joined %s",
                                     weechat_prefix("join"), ev->room);
            /* ask who is here; the reply is parsed into the nicklist */
            {
                char cmd[RRC_MAX_ROOM + 8];
                snprintf(cmd, sizeof(cmd), "/who %s", ev->room);
                if (rrc_say(&s->session, RRC_T_MSG, ev->room, cmd, now_s(), &err) == 0)
                    r->who_pending = 1;
            }
        } else if (r) {
            if (ev->n_members == 1)
                member_upsert(r, ev->members[0], RNS_HASH_LEN, ev->nick);
            else if (ev->nick)
                member_upsert(r, NULL, 0, ev->nick);
            snprintf(name, sizeof(name), "%s", ev->nick ? ev->nick : "someone");
            if (!ev->nick && ev->n_members == 1)
                short_hash(ev->members[0], RNS_HASH_LEN, name);
            weechat_printf_date_tags(r->buffer, 0, "rrc_join,log4", "%s%s has joined %s",
                                     weechat_prefix("join"), name, ev->room);
        }
        break;

    case RRC_EV_PARTED:
        if (!r)
            break;
        if (ev->own) {
            r->joined = 0;
            members_clear(r);
            weechat_printf_date_tags(r->buffer, 0, "rrc_part,log4", "%syou left %s",
                                     weechat_prefix("quit"), ev->room);
        } else {
            snprintf(name, sizeof(name), "%s", ev->nick ? ev->nick : "someone");
            if (ev->n_members == 1) {
                if (!ev->nick)
                    short_hash(ev->members[0], RNS_HASH_LEN, name);
                member_remove(r, ev->members[0], RNS_HASH_LEN, NULL);
            } else if (ev->nick) {
                member_remove(r, NULL, 0, ev->nick);
            }
            weechat_printf_date_tags(r->buffer, 0, "rrc_part,log4", "%s%s has left %s",
                                     weechat_prefix("quit"), name, ev->room);
        }
        break;

    case RRC_EV_MSG:
    case RRC_EV_ACTION:
        if (ev->room && !r)
            r = room_open(s, ev->room, 0);
        print_message(s, r, ev);
        break;

    case RRC_EV_NOTICE:
        if (!ev->src || memcmp(ev->src, s->hub_identity, RNS_HASH_LEN) != 0) {
            /* from a person, relayed by the hub: say who, and never read it
             * as the hub's own word (topic, member list) */
            char *color;
            sender_name(r, ev, name, sizeof(name));
            color = nick_color(name);
            snprintf(prefix, sizeof(prefix), "%s-%s%s%s-\t", weechat_prefix("network"),
                     color ? color : "", name, weechat_color("reset"));
            free(color);
            print_lines(r && r->buffer ? r->buffer : s->buffer, "rrc_notice,notify_message,log1",
                        prefix, ev->text);
            break;
        }
        if (handle_who_notice(s, ev->text))
            break;
        handle_topic_notice(s, ev->text);
        snprintf(prefix, sizeof(prefix), "%s", weechat_prefix("network"));
        print_lines(r && r->buffer ? r->buffer : s->buffer,
                    r ? "rrc_notice,notify_none,log3" : "rrc_notice,log3", prefix, ev->text);
        break;

    case RRC_EV_ERROR:
        /* a refused JOIN, or "kicked from ROOM" (rrcd sends no PARTED then):
         * either way we are not in the room */
        if (r && (ev->own || strncmp(ev->text, "kicked", 6) == 0)) {
            r->joined = 0;
            members_clear(r);
        }
        print_lines(r && r->buffer ? r->buffer : s->buffer, "rrc_error,log3",
                    weechat_prefix("error"), ev->text);
        break;

    case RRC_EV_PONG:
        server_print(s, "network", "pong from the hub: %.0f ms", ev->rtt_ms);
        break;

    case RRC_EV_HELLO_TIMEOUT:
        rns_client_close(s->link, now_s(), "the hub did not answer HELLO");
        break;
    }
}

/* ---- connection ---- */

static int
read_cb(const void *pointer, void *data, int fd);

static void
on_frame_cb(void *ctx, const uint8_t *frame, size_t len)
{
    struct rrc_server *s = ctx;

    if (s->link)
        rns_client_inbound(s->link, frame, len, now_s());
}

static void
server_after_io(struct rrc_server *s)
{
    if (s->close_pending) {
        char reason[sizeof(s->close_reason)];
        snprintf(reason, sizeof(reason), "%s", s->close_reason);
        server_disconnect(s, reason, !s->user_disconnect);
    }
}

static int
read_cb(const void *pointer, void *data, int fd)
{
    struct rrc_server *s = (struct rrc_server *)pointer;
    uint8_t buf[8192];
    ssize_t n;
    int reads;

    /* at most 32 reads per wakeup, so a flood can't hold WeeChat's main loop */
    for (reads = 0; reads < 32; reads++) {
        n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            hdlc_rx_feed(&s->rx, buf, (size_t)n, &on_frame_cb, s);
            if (s->close_pending)
                break;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (n < 0 && errno == EINTR)
            continue;
        s->close_pending = 1;
        snprintf(s->close_reason, sizeof(s->close_reason), "%s",
                 n == 0 ? "connection closed by the Reticulum node" : strerror(errno));
        break;
    }
    server_after_io(s);
    return WEECHAT_RC_OK;
}

static void
server_link_up(struct rrc_server *s, int fd)
{
    struct rns_callbacks rcb = { &net_send_cb, &link_state_cb, &link_data_cb, &link_log_cb };
    struct rrc_callbacks scb = { &session_send_cb, &session_mdu_cb, &session_event_cb };
    uint8_t hub[RNS_HASH_LEN];
    const char *nick;
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    s->fd = fd;
    s->conn = CONN_UP;
    s->out_len = 0;
    hdlc_rx_init(&s->rx);
    s->hook_read = weechat_hook_fd(fd, 1, 0, 0, &read_cb, s, NULL);

    rns_unhex(server_value(s->name, "hub"), hub, RNS_HASH_LEN);
    s->link = calloc(1, sizeof(*s->link));
    if (!s->link) {
        server_disconnect(s, "out of memory", 0);
        return;
    }
    rns_client_init(s->link, &identity, hub, s->shared, &rcb, s);
    s->link->path_timeout = weechat_config_integer(opt_path_timeout);
    nick = server_value(s->name, "nick");
    rrc_session_init(&s->session, identity.hash, nick, &scb, s);
    s->session_live = 0;
    s->welcomed = 0;
    server_print(s, "network", "finding a path to the hub...");
    rns_client_start(s->link, now_s());
    server_after_io(s);
}

static int
connect_cb(const void *pointer, void *data, int status, int gnutls_rc, int sock,
           const char *error, const char *ip_address)
{
    struct rrc_server *s = (struct rrc_server *)pointer;

    s->hook_connect = NULL;
    if (status == WEECHAT_HOOK_CONNECT_OK) {
        server_print(s, "network", "connected to the Reticulum node%s%s",
                     ip_address ? " at " : "", ip_address ? ip_address : "");
        server_link_up(s, sock);
    } else {
        s->conn = CONN_IDLE;
        server_print(s, "error", "cannot connect to %s: %s",
                     server_value(s->name, "address"),
                     error && error[0] ? error : "connection failed");
        server_disconnect(s, NULL, !s->user_disconnect);
    }
    return WEECHAT_RC_OK;
}

/* "unix:NAME", "shared[:HOST:PORT]" or "[tcp:]HOST:PORT" */
static int
server_connect(struct rrc_server *s)
{
    const char *address = server_value(s->name, "address");
    uint8_t hub[RNS_HASH_LEN];
    char host[256], *colon;
    const char *spec;
    long port;

    if (s->conn != CONN_IDLE) {
        server_print(s, "error", "already connected or connecting");
        return -1;
    }
    server_buffer_open(s);
    if (rns_unhex(server_value(s->name, "hub"), hub, RNS_HASH_LEN) != 0) {
        server_print(s, "error", "rrc.server.%s.hub is not a 32-character hub hash", s->name);
        return -1;
    }
    if (identity_ensure(s->buffer) != 0)
        return -1;
    s->user_disconnect = 0;
    s->close_pending = 0;
    s->reconnect_at = 0;
    if (!address[0])
        address = "unix:default";

    if (strncmp(address, "unix:", 5) == 0) {
        struct sockaddr_un sa;
        size_t n = strlen(address + 5);
        int fd;
        if (n == 0 || n + 5 > sizeof(sa.sun_path) - 1) {
            server_print(s, "error", "bad unix socket name in %s", address);
            return -1;
        }
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        memcpy(sa.sun_path + 1, "rns/", 4);   /* abstract: "\0rns/NAME" */
        memcpy(sa.sun_path + 5, address + 5, n);
        if (fd < 0 || connect(fd, (struct sockaddr *)&sa,
                              (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 5 + n)) != 0) {
            server_print(s, "error", "cannot reach the shared instance %s: %s (is rnsd running?)",
                         address + 5, strerror(errno));
            if (fd >= 0)
                close(fd);
            server_disconnect(s, NULL, 1);
            return -1;
        }
        s->shared = 1;
        server_print(s, "network", "connected to the Reticulum shared instance %s", address + 5);
        server_link_up(s, fd);
        return 0;
    }

    s->shared = 0;
    spec = address;
    if (strncmp(spec, "shared", 6) == 0) {
        s->shared = 1;
        spec += 6;
        if (*spec == ':')
            spec++;
        if (!*spec)
            spec = "127.0.0.1:37428";
    } else if (strncmp(spec, "tcp:", 4) == 0) {
        spec += 4;
    }
    snprintf(host, sizeof(host), "%s", spec);
    colon = strrchr(host, ':');
    port = colon ? strtol(colon + 1, NULL, 10) : 0;
    if (!colon || port <= 0 || port > 65535) {
        server_print(s, "error", "bad address \"%s\" (use unix:NAME, shared:HOST:PORT or "
                     "tcp:HOST:PORT)", address);
        return -1;
    }
    *colon = '\0';
    if (host[0] == '[' && colon[-1] == ']') {
        memmove(host, host + 1, strlen(host));
        host[strlen(host) - 1] = '\0';
    }
    s->conn = CONN_CONNECTING;
    server_print(s, "network", "connecting to %s...", address);
    s->hook_connect = weechat_hook_connect(NULL, host, (int)port, 1, 0, NULL, NULL, 0, NULL,
                                           NULL, &connect_cb, s, NULL);
    if (!s->hook_connect) {
        s->conn = CONN_IDLE;
        return -1;
    }
    return 0;
}

static void
server_disconnect(struct rrc_server *s, const char *reason, int reconnect)
{
    struct rrc_room *r;
    double now = now_s();

    if (s->hook_connect) {
        weechat_unhook(s->hook_connect);
        s->hook_connect = NULL;
    }
    if (s->link) {
        if (s->link->state != RNS_CLOSED && s->conn == CONN_UP) {
            rns_client_close(s->link, now, "disconnecting");
            flush_out(s);
        }
        rns_client_wipe(s->link);
        free(s->link);
        s->link = NULL;
    }
    rrc_session_free(&s->session);
    s->session_live = 0;
    if (s->hook_read) {
        weechat_unhook(s->hook_read);
        s->hook_read = NULL;
    }
    if (s->hook_write) {
        weechat_unhook(s->hook_write);
        s->hook_write = NULL;
    }
    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
    free(s->out);
    s->out = NULL;
    s->out_len = s->out_cap = 0;
    s->close_pending = 0;
    if (s->conn != CONN_IDLE || reason) {
        if (reason)
            server_print(s, "network", "disconnected: %s", reason);
        for (r = s->rooms; r; r = r->next) {
            if (r->buffer && r->joined)
                weechat_printf_date_tags(r->buffer, 0, "rrc_part,log4", "%sdisconnected%s%s",
                                         weechat_prefix("network"), reason ? ": " : "",
                                         reason ? reason : "");
            r->joined = 0;
            members_clear(r);
        }
    }
    s->conn = CONN_IDLE;
    s->welcomed = 0;
    if (reconnect && !s->user_disconnect) {
        s->reconnect_delay = s->reconnect_delay ? s->reconnect_delay * 2 : RECONNECT_MIN;
        if (s->reconnect_delay > RECONNECT_MAX)
            s->reconnect_delay = RECONNECT_MAX;
        s->reconnect_at = now + s->reconnect_delay;
        server_print(s, "network", "reconnecting in %d seconds", s->reconnect_delay);
    } else {
        s->reconnect_at = 0;
    }
}

static struct rrc_server *
server_new(const char *name)
{
    struct rrc_server *s = calloc(1, sizeof(*s));

    if (!s)
        return NULL;
    snprintf(s->name, sizeof(s->name), "%s", name);
    s->fd = -1;
    s->next = servers;
    servers = s;
    return s;
}

static void
server_free(struct rrc_server *s)
{
    struct rrc_server **pp;

    s->user_disconnect = 1;
    server_disconnect(s, NULL, 0);
    while (s->rooms) {
        struct t_gui_buffer *b = s->rooms->buffer;
        s->rooms->buffer = NULL;
        room_free(s, s->rooms);
        if (b)
            weechat_buffer_close(b);
    }
    for (pp = &servers; *pp; pp = &(*pp)->next) {
        if (*pp == s) {
            *pp = s->next;
            break;
        }
    }
    free(s);
}

/* Make runtime entries for every server named in the config. */
static void
servers_from_config(void)
{
    struct t_hdata *hdata = weechat_hdata_get("config_option");
    struct t_config_option *o;
    char name[64];
    const char *full, *dot;
    size_t n;

    o = weechat_hdata_pointer(weechat_hdata_get("config_section"), section_server, "options");
    for (; o; o = weechat_hdata_move(hdata, o, 1)) {
        full = weechat_hdata_string(hdata, o, "name");
        dot = full ? strrchr(full, '.') : NULL;
        if (!dot)
            continue;
        n = (size_t)(dot - full);
        if (n == 0 || n >= sizeof(name))
            continue;
        memcpy(name, full, n);
        name[n] = '\0';
        if (!server_find(name))
            server_new(name);
    }
}

/* ---- sending ---- */

/* Show a line we sent, as the hub will not echo it back to us. */
static void
echo_own(struct rrc_server *s, struct rrc_room *r, int type, const char *text)
{
    char tags[256], prefix[256], tagnick[RRC_MAX_NICK];
    const char *nick = s->session.nick[0] ? s->session.nick : NULL;

    tag_safe(nick ? nick : "self", tagnick, sizeof(tagnick));
    if (type == RRC_T_ACTION) {
        snprintf(tags, sizeof(tags), "rrc_action,notify_none,self_msg,no_highlight,nick_%s,log1",
                 tagnick);
        snprintf(prefix, sizeof(prefix), "%s%s%s%s ", weechat_prefix("action"),
                 weechat_color("chat_nick_self"), nick ? nick : "me", weechat_color("reset"));
    } else {
        snprintf(tags, sizeof(tags), "rrc_msg,notify_none,self_msg,no_highlight,nick_%s,log1",
                 tagnick);
        snprintf(prefix, sizeof(prefix), "%s%s%s\t", weechat_color("chat_nick_self"),
                 nick ? nick : "me", weechat_color("reset"));
    }
    print_lines(r->buffer, tags, prefix, text);
}

/* Send text to a room, split into lines and into pieces that fit. */
static void
room_send(struct rrc_server *s, struct rrc_room *r, int type, const char *text)
{
    const char *line = text, *nl, *err;
    char piece[RRC_MAX_TEXT];
    size_t len, max, take;

    if (!s->welcomed || !r->joined) {
        weechat_printf(r->buffer, "%snot in %s (not connected)", weechat_prefix("error"), r->name);
        return;
    }
    /* "/cmd" is a hub command: send it whole and let the hub's reply speak */
    if (type == RRC_T_MSG && text[0] == '/') {
        if (rrc_say(&s->session, RRC_T_MSG, r->name, text, now_s(), &err) != 0)
            weechat_printf(r->buffer, "%scannot send: %s", weechat_prefix("error"), err);
        return;
    }
    max = rrc_max_body(&s->session, r->name);
    if (max > sizeof(piece) - 1)
        max = sizeof(piece) - 1;
    for (; line && *line; line = nl ? nl + 1 : NULL) {
        nl = strchr(line, '\n');
        len = nl ? (size_t)(nl - line) : strlen(line);
        while (len > 0) {
            take = len < max ? len : max;
            while (take < len && take > 0 && ((uint8_t)line[take] & 0xc0) == 0x80)
                take--;   /* don't split a UTF-8 sequence */
            if (take == 0)
                break;
            memcpy(piece, line, take);
            piece[take] = '\0';
            if (rrc_say(&s->session, type, r->name, piece, now_s(), &err) != 0) {
                weechat_printf(r->buffer, "%scannot send: %s", weechat_prefix("error"), err);
                return;
            }
            echo_own(s, r, type, piece);
            line += take;
            len -= take;
        }
    }
}

/* ---- interface for scripts ---- */

/* "rrc_input_send" signal, the RRC counterpart of irc_input_send:
 *   "server;room;flags;text"
 * flags (comma-separated, may be empty): "raw" sends text as one message,
 * exactly as given (no splitting, no hub commands) and fails if it does not
 * fit; without it, text is handled as if typed in the room buffer.
 * Returns WEECHAT_RC_OK when queued, WEECHAT_RC_ERROR otherwise. */
static int
input_send_signal_cb(const void *pointer, void *data, const char *signal,
                     const char *type_data, void *signal_data)
{
    const char *msg = signal_data, *p[3], *text, *err;
    char server[64], room[RRC_MAX_ROOM], flags[64];
    struct rrc_server *s;
    struct rrc_room *r;
    size_t n;
    int i, raw;

    if (!msg || strcmp(type_data, WEECHAT_HOOK_SIGNAL_STRING) != 0)
        return WEECHAT_RC_ERROR;
    text = msg;
    for (i = 0; i < 3; i++) {
        p[i] = strchr(text, ';');
        if (!p[i])
            return WEECHAT_RC_ERROR;
        text = p[i] + 1;
    }
    n = (size_t)(p[0] - msg);
    if (n == 0 || n >= sizeof(server))
        return WEECHAT_RC_ERROR;
    memcpy(server, msg, n);
    server[n] = '\0';
    n = (size_t)(p[1] - p[0] - 1);
    if (n >= sizeof(room))
        return WEECHAT_RC_ERROR;
    memcpy(room, p[0] + 1, n);
    room[n] = '\0';
    n = (size_t)(p[2] - p[1] - 1);
    if (n >= sizeof(flags))
        return WEECHAT_RC_ERROR;
    memcpy(flags, p[1] + 1, n);
    flags[n] = '\0';
    raw = strstr(flags, "raw") != NULL;

    s = server_find(server);
    r = s ? room_find(s, room) : NULL;
    if (!s || !r || !r->buffer || !s->welcomed || !r->joined || !*text)
        return WEECHAT_RC_ERROR;
    if (!raw) {
        room_send(s, r, RRC_T_MSG, text);
        return WEECHAT_RC_OK;
    }
    if (strchr(text, '\n') || rrc_say(&s->session, RRC_T_MSG, r->name, text, now_s(), &err) != 0)
        return WEECHAT_RC_ERROR;
    echo_own(s, r, RRC_T_MSG, text);
    return WEECHAT_RC_OK;
}

/* info "rrc_max_body", arguments "server,room": the largest message body in
 * bytes that fits one packet to that room now ("0" when not joined).
 * info "rrc_queue", arguments "server": messages waiting for the rate limit. */
static char *
info_cb(const void *pointer, void *data, const char *info_name, const char *arguments)
{
    char server[64], buf[32];
    const char *comma;
    struct rrc_server *s;
    struct rrc_room *r;
    size_t n;

    if (!arguments)
        return NULL;
    comma = strchr(arguments, ',');
    n = comma ? (size_t)(comma - arguments) : strlen(arguments);
    if (n == 0 || n >= sizeof(server))
        return NULL;
    memcpy(server, arguments, n);
    server[n] = '\0';
    s = server_find(server);
    if (!s)
        return NULL;
    if (strcmp(info_name, "rrc_queue") == 0) {
        snprintf(buf, sizeof(buf), "%zu", s->session_live ? s->session.queued : 0);
        return strdup(buf);
    }
    r = comma ? room_find(s, comma + 1) : NULL;
    snprintf(buf, sizeof(buf), "%zu",
             (r && r->joined && s->welcomed) ? rrc_max_body(&s->session, r->name) : 0);
    return strdup(buf);
}

static int
room_input_cb(const void *pointer, void *data, struct t_gui_buffer *buffer, const char *input)
{
    struct rrc_room *r;
    struct rrc_server *s = buffer_context(buffer, &r);

    /* "//cmd" typed reaches us as "/cmd"; via /command or the fifo it may not */
    if (input[0] == '/' && input[1] == '/')
        input++;
    if (s && r)
        room_send(s, r, RRC_T_MSG, input);
    return WEECHAT_RC_OK;
}

static int
room_close_cb(const void *pointer, void *data, struct t_gui_buffer *buffer)
{
    struct rrc_room *r;
    struct rrc_server *s = buffer_context(buffer, &r);
    const char *err;

    if (!s || !r)
        return WEECHAT_RC_OK;
    if (r->joined && s->welcomed)
        rrc_part(&s->session, r->name, now_s(), &err);
    r->buffer = NULL;
    room_free(s, r);
    return WEECHAT_RC_OK;
}

static int
server_input_cb(const void *pointer, void *data, struct t_gui_buffer *buffer, const char *input)
{
    struct rrc_server *s = buffer_context(buffer, NULL);
    const char *err;

    if (!s)
        return WEECHAT_RC_OK;
    if (input[0] == '/' && input[1] == '/')
        input++;
    if (input[0] != '/') {
        weechat_printf(buffer, "%sthis is the hub buffer: type //command to send a hub command "
                       "(//list, //who ROOM), or /join ROOM", weechat_prefix("error"));
        return WEECHAT_RC_OK;
    }
    if (!s->welcomed) {
        weechat_printf(buffer, "%snot connected", weechat_prefix("error"));
        return WEECHAT_RC_OK;
    }
    if (rrc_say(&s->session, RRC_T_MSG, NULL, input, now_s(), &err) != 0)
        weechat_printf(buffer, "%scannot send: %s", weechat_prefix("error"), err);
    return WEECHAT_RC_OK;
}

static int
server_close_cb(const void *pointer, void *data, struct t_gui_buffer *buffer)
{
    struct rrc_server *s = buffer_context(buffer, NULL);

    if (s) {
        s->buffer = NULL;
        s->user_disconnect = 1;
        server_disconnect(s, NULL, 0);
    }
    return WEECHAT_RC_OK;
}

/* ---- commands ---- */

static void
do_join(struct rrc_server *s, struct t_gui_buffer *buffer, const char *room)
{
    char norm[RRC_MAX_ROOM];
    const char *err;
    struct rrc_room *r;

    if (!rrc_normalize_room(room, norm, sizeof(norm))) {
        weechat_printf(buffer, "%sinvalid room name", weechat_prefix("error"));
        return;
    }
    r = room_open(s, norm, 1);
    if (!r)
        return;
    if (!s->welcomed) {
        weechat_printf(r->buffer, "%snot connected yet: %s will be joined on connect",
                       weechat_prefix("network"), norm);
        return;
    }
    if (rrc_join(&s->session, norm, now_s(), &err) != 0)
        weechat_printf(r->buffer, "%scannot join: %s", weechat_prefix("error"), err);
}

static void
do_part(struct rrc_server *s, struct rrc_room *r, struct t_gui_buffer *buffer)
{
    const char *err;

    if (!r) {
        weechat_printf(buffer, "%sno such room here", weechat_prefix("error"));
        return;
    }
    if (!s->welcomed || !r->joined) {
        weechat_printf(r->buffer, "%snot in %s", weechat_prefix("error"), r->name);
        return;
    }
    if (rrc_part(&s->session, r->name, now_s(), &err) != 0)
        weechat_printf(r->buffer, "%scannot part: %s", weechat_prefix("error"), err);
}

static void
do_nick(struct rrc_server *s, struct t_gui_buffer *buffer, const char *nick)
{
    struct rrc_room *r;

    set_server_option(s->name, "nick", nick);
    rrc_set_nick(&s->session, nick);
    set_nick_localvar(s);
    for (r = s->rooms; r; r = r->next)
        if (r->joined)
            member_upsert(r, s->session.self, RNS_HASH_LEN, s->session.nick);
    weechat_printf(buffer, "%syou are now known as %s (nicknames are advisory: the hub and "
                   "others see your identity hash)", weechat_prefix("network"), s->session.nick);
}

static void
cmd_list(struct t_gui_buffer *buffer)
{
    struct rrc_server *s;

    if (!servers) {
        weechat_printf(NULL, "rrc: no servers (add one with /rrc add)");
        return;
    }
    weechat_printf(buffer, "RRC servers:");
    for (s = servers; s; s = s->next)
        weechat_printf(buffer, "  %s%s%s  hub %s via %s  %s",
                       weechat_color("chat_server"), s->name, weechat_color("reset"),
                       server_value(s->name, "hub"),
                       server_value(s->name, "address")[0] ? server_value(s->name, "address")
                                                           : "unix:default",
                       s->welcomed ? "connected"
                       : s->conn != CONN_IDLE || s->link ? (s->link ? rns_state_name(s->link->state)
                                                                     : "connecting")
                       : "not connected");
}

/* rrc://HUBHASH[/room] -> hub, room */
static int
parse_rrc_url(const char *arg, char *hub, size_t hub_size, char *room, size_t room_size)
{
    const char *p = arg, *slash;
    size_t n;

    room[0] = '\0';
    if (strncmp(p, "rrc://", 6) == 0)
        p += 6;
    slash = strchr(p, '/');
    n = slash ? (size_t)(slash - p) : strlen(p);
    if (n != 2 * RNS_HASH_LEN || n >= hub_size)
        return -1;
    memcpy(hub, p, n);
    hub[n] = '\0';
    if (slash && slash[1])
        snprintf(room, room_size, "%s", slash + 1);
    return 0;
}

static int
rrc_command_cb(const void *pointer, void *data, struct t_gui_buffer *buffer,
               int argc, char **argv, char **argv_eol)
{
    struct rrc_server *s;
    struct rrc_room *r;
    const char *err;
    char hex[2 * RNS_HASH_LEN + 1];
    int i;

    if (argc < 2 || strcmp(argv[1], "list") == 0) {
        cmd_list(buffer);
        return WEECHAT_RC_OK;
    }

    if (strcmp(argv[1], "add") == 0) {
        char hub[2 * RNS_HASH_LEN + 1], room[RRC_MAX_ROOM];
        uint8_t tmp[RNS_HASH_LEN];
        if (argc < 4) {
            weechat_printf(buffer, "%susage: /rrc add <name> <hub-hash|rrc://hub/room> "
                           "[<address>] [-nick <nick>] [-autojoin <rooms>] [-autoconnect]",
                           weechat_prefix("error"));
            return WEECHAT_RC_OK;
        }
        if (strchr(argv[2], '.') || server_find(argv[2])) {
            weechat_printf(buffer, "%sserver \"%s\" exists or has a dot in its name",
                           weechat_prefix("error"), argv[2]);
            return WEECHAT_RC_OK;
        }
        if (parse_rrc_url(argv[3], hub, sizeof(hub), room, sizeof(room)) != 0
            || rns_unhex(hub, tmp, RNS_HASH_LEN) != 0) {
            weechat_printf(buffer, "%s\"%s\" is not a hub hash", weechat_prefix("error"), argv[3]);
            return WEECHAT_RC_OK;
        }
        set_server_option(argv[2], "hub", hub);
        set_server_option(argv[2], "address", "unix:default");
        set_server_option(argv[2], "nick", "");
        set_server_option(argv[2], "autojoin", room);
        set_server_option(argv[2], "autoconnect", "off");
        for (i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-nick") == 0 && i + 1 < argc)
                set_server_option(argv[2], "nick", argv[++i]);
            else if (strcmp(argv[i], "-autojoin") == 0 && i + 1 < argc)
                set_server_option(argv[2], "autojoin", argv[++i]);
            else if (strcmp(argv[i], "-autoconnect") == 0)
                set_server_option(argv[2], "autoconnect", "on");
            else if (argv[i][0] != '-')
                set_server_option(argv[2], "address", argv[i]);
        }
        server_new(argv[2]);
        weechat_printf(buffer, "rrc: server %s added (hub %s via %s); /rrc connect %s",
                       argv[2], hub, server_value(argv[2], "address"), argv[2]);
        return WEECHAT_RC_OK;
    }

    if (strcmp(argv[1], "del") == 0) {
        if (argc < 3 || !(s = server_find(argv[2]))) {
            weechat_printf(buffer, "%sno such server", weechat_prefix("error"));
            return WEECHAT_RC_OK;
        }
        for (i = 0; SERVER_KEYS[i]; i++) {
            struct t_config_option *o = server_option(s->name, SERVER_KEYS[i]);
            if (o)
                weechat_config_option_free(o);
        }
        if (s->buffer) {
            struct t_gui_buffer *b = s->buffer;
            s->buffer = NULL;
            weechat_buffer_close(b);
        }
        weechat_printf(buffer, "rrc: server %s deleted", argv[2]);
        server_free(s);
        return WEECHAT_RC_OK;
    }

    if (strcmp(argv[1], "identity") == 0) {
        if (identity_ensure(buffer) == 0) {
            rns_hex(identity.hash, RNS_HASH_LEN, hex);
            weechat_printf(buffer, "rrc: identity %s", hex);
        }
        return WEECHAT_RC_OK;
    }

    if (strcmp(argv[1], "connect") == 0) {
        if (argc >= 3 && strcmp(argv[2], "-all") == 0) {
            for (s = servers; s; s = s->next)
                if (s->conn == CONN_IDLE)
                    server_connect(s);
            return WEECHAT_RC_OK;
        }
        s = argc >= 3 ? server_find(argv[2]) : buffer_context(buffer, NULL);
        if (!s) {
            weechat_printf(buffer, "%sno such server (see /rrc list)", weechat_prefix("error"));
            return WEECHAT_RC_OK;
        }
        server_connect(s);
        return WEECHAT_RC_OK;
    }

    if (strcmp(argv[1], "disconnect") == 0) {
        s = argc >= 3 ? server_find(argv[2]) : buffer_context(buffer, NULL);
        if (!s) {
            weechat_printf(buffer, "%sno such server", weechat_prefix("error"));
            return WEECHAT_RC_OK;
        }
        s->user_disconnect = 1;
        server_disconnect(s, "disconnected by you", 0);
        return WEECHAT_RC_OK;
    }

    s = buffer_context(buffer, &r);
    if (!s) {
        weechat_printf(buffer, "%srun this in an RRC buffer", weechat_prefix("error"));
        return WEECHAT_RC_OK;
    }
    if (strcmp(argv[1], "join") == 0 && argc >= 3) {
        do_join(s, buffer, argv[2]);
    } else if (strcmp(argv[1], "part") == 0) {
        do_part(s, argc >= 3 ? room_find(s, argv[2]) : r, buffer);
    } else if (strcmp(argv[1], "nick") == 0 && argc >= 3) {
        do_nick(s, buffer, argv_eol[2]);
    } else if (strcmp(argv[1], "ping") == 0) {
        if (!s->welcomed || rrc_ping(&s->session, now_s(), &err) != 0)
            weechat_printf(buffer, "%snot connected", weechat_prefix("error"));
    } else if (strcmp(argv[1], "status") == 0) {
        rns_hex(identity.hash, RNS_HASH_LEN, hex);
        weechat_printf(buffer, "rrc %s: hub %s%s%s%s via %s", s->name, server_value(s->name, "hub"),
                       s->hub_name[0] ? " (" : "", s->hub_name, s->hub_name[0] ? ")" : "",
                       server_value(s->name, "address"));
        weechat_printf(buffer, "  identity %s, nick %s", identity_loaded ? hex : "(not loaded)",
                       s->session.nick[0] ? s->session.nick : "(none)");
        if (s->link)
            weechat_printf(buffer, "  link %s, %d hop%s, rtt %.0f ms, mdu %zu, %llu packets out, "
                           "%llu in, queue %zu", rns_state_name(s->link->state), s->link->hops,
                           s->link->hops == 1 ? "" : "s", s->link->rtt * 1000.0, s->link->mdu,
                           (unsigned long long)s->link->tx_packets,
                           (unsigned long long)s->link->rx_packets, s->session.queued);
        if (s->welcomed)
            weechat_printf(buffer, "  hub limits: body %u bytes, nick %u, %u rooms, %u messages/min",
                           s->session.limits.max_msg_body_bytes, s->session.limits.max_nick_bytes,
                           s->session.limits.max_rooms_per_session,
                           s->session.limits.rate_limit_msgs_per_minute);
    } else {
        weechat_printf(buffer, "%sunknown /rrc command (see /help rrc)", weechat_prefix("error"));
    }
    return WEECHAT_RC_OK;
}

/* rrcd's hub commands; needs_room: the room comes first in its arguments,
 * and in a room buffer it is filled in, IRC style ("/kick nick") */
static const struct { const char *verb; int needs_room; } HUB_COMMANDS[] = {
    { "who", 0 }, { "names", 0 }, { "list", 0 }, { "stats", 0 }, { "kline", 0 },
    { "topic", 1 }, { "register", 1 }, { "unregister", 1 }, { "mode", 1 },
    { "op", 1 }, { "deop", 1 }, { "voice", 1 }, { "devoice", 1 },
    { "kick", 1 }, { "ban", 1 }, { "invite", 1 },
    { NULL, 0 },
};

static void
hub_command(struct rrc_server *s, struct rrc_room *r, struct t_gui_buffer *buffer,
            const char *verb, const char *args)
{
    char cmd[RRC_MAX_TEXT], first[RRC_MAX_ROOM];
    const char *err, *sp;
    size_t n;
    int i, insert = 0;

    if (!s->welcomed) {
        weechat_printf(buffer, "%snot connected", weechat_prefix("error"));
        return;
    }
    for (i = 0; HUB_COMMANDS[i].verb; i++)
        if (strcmp(HUB_COMMANDS[i].verb, verb) == 0)
            insert = HUB_COMMANDS[i].needs_room && r;
    if (insert) {
        /* unless the room was named already */
        sp = strchr(args, ' ');
        n = sp ? (size_t)(sp - args) : strlen(args);
        if (n && n < sizeof(first)) {
            memcpy(first, args, n);
            first[n] = '\0';
            if (strcmp(first, r->name) == 0 || (room_find(s, first) && strcmp(verb, "topic") != 0))
                insert = 0;
        }
    }
    if (insert)
        snprintf(cmd, sizeof(cmd), "/%s %s%s%s", verb, r->name, *args ? " " : "", args);
    else
        snprintf(cmd, sizeof(cmd), "/%s%s%s", verb, *args ? " " : "", args);
    if (rrc_say(&s->session, RRC_T_MSG, r ? r->name : NULL, cmd, now_s(), &err) != 0)
        weechat_printf(buffer, "%scannot send: %s", weechat_prefix("error"), err);
}

/* /join, /part, /me, /nick and the hub commands typed in an RRC buffer */
static int
command_run_cb(const void *pointer, void *data, struct t_gui_buffer *buffer, const char *command)
{
    struct rrc_room *r;
    struct rrc_server *s = buffer_context(buffer, &r);
    const char *verb = (const char *)pointer, *args;

    if (!s)
        return WEECHAT_RC_OK;
    args = command + 1 + strlen(verb);
    while (*args == ' ')
        args++;
    if (strcmp(verb, "join") == 0) {
        if (*args)
            do_join(s, buffer, args);
    } else if (strcmp(verb, "part") == 0) {
        do_part(s, *args ? room_find(s, args) : r, buffer);
    } else if (strcmp(verb, "me") == 0) {
        if (r && *args)
            room_send(s, r, RRC_T_ACTION, args);
    } else if (strcmp(verb, "nick") == 0) {
        if (*args)
            do_nick(s, buffer, args);
    } else {
        hub_command(s, r, buffer, verb, args);
    }
    return WEECHAT_RC_OK_EAT;
}

static int
completion_servers_cb(const void *pointer, void *data, const char *item,
                      struct t_gui_buffer *buffer, struct t_gui_completion *completion)
{
    struct rrc_server *s;

    for (s = servers; s; s = s->next)
        weechat_completion_list_add(completion, s->name, 0, WEECHAT_LIST_POS_SORT);
    return WEECHAT_RC_OK;
}

/* ---- timer ---- */

static int
timer_cb(const void *pointer, void *data, int remaining_calls)
{
    struct rrc_server *s, *next;
    double now = now_s();

    for (s = servers; s; s = next) {
        next = s->next;
        if (s->link) {
            rns_client_tick(s->link, now);
            if (s->session_live && s->link && s->link->state == RNS_ACTIVE)
                rrc_session_tick(&s->session, now);
            server_after_io(s);
        } else if (s->conn == CONN_IDLE && s->reconnect_at > 0 && now >= s->reconnect_at) {
            s->reconnect_at = 0;
            server_print(s, "network", "reconnecting...");
            server_connect(s);
        }
    }
    return WEECHAT_RC_OK;
}

/* ---- plugin ---- */

static const char *RUN_VERBS[] = { "join", "part", "me", "nick", NULL };

int
weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
    struct rrc_server *s;
    char cmd[32];
    int i;

    weechat_plugin = plugin;
    if (config_init() != 0)
        return WEECHAT_RC_ERROR;
    weechat_config_read(config_file);
    servers_from_config();

    weechat_hook_command(
        "rrc", "Reticulum Relay Chat",
        "list"
        " || add <name> <hub-hash|rrc://hub/room> [<address>] [-nick <nick>] "
        "[-autojoin <rooms>] [-autoconnect]"
        " || del <name>"
        " || connect <name>|-all"
        " || disconnect [<name>]"
        " || join <room>"
        " || part [<room>]"
        " || nick <nick>"
        " || ping"
        " || status"
        " || identity",
        WEECHAT_CMD_ARGS_DESC(
            "raw[list]: list servers",
            "raw[add]: add a server; <address> is where Reticulum is reached:",
            "  unix:NAME       the local rnsd shared instance (default: unix:default)",
            "  shared:HOST:PORT a shared instance over TCP (rnsd's shared_instance_port)",
            "  tcp:HOST:PORT   a TCPServerInterface on a Reticulum transport node",
            "raw[del]: delete a server",
            "raw[connect]: connect (find a path, link, identify, join autojoin rooms)",
            "raw[disconnect]: close the link",
            "raw[join]: join a room (rooms are created on demand by the hub)",
            "raw[part]: leave a room",
            "raw[nick]: set your advisory nickname",
            "raw[ping]: measure the round trip to the hub",
            "raw[status]: link and hub details",
            "raw[identity]: show your identity hash",
            "",
            "In RRC buffers, /join, /part, /me and /nick work as usual, and so do the hub's",
            "commands: /who, /names, /list, /topic, /register, /unregister, /mode, /op, /deop,",
            "/voice, /devoice, /kick, /ban, /invite, /kline, /stats. In a room buffer the room",
            "is filled in (/kick nick, /mode +t). //cmd sends any other /cmd to the hub.",
            "",
            "Options: /set rrc.server.<name>.* (hub, address, nick, autojoin, autoconnect)",
            "and /set rrc.network.*"),
        "list|add|del|connect|disconnect|join|part|nick|ping|status|identity %(rrc_servers)",
        &rrc_command_cb, NULL, NULL);
    weechat_hook_completion("rrc_servers", "RRC servers", &completion_servers_cb, NULL, NULL);
    for (i = 0; RUN_VERBS[i]; i++) {
        snprintf(cmd, sizeof(cmd), "/%s", RUN_VERBS[i]);
        weechat_hook_command_run(cmd, &command_run_cb, RUN_VERBS[i], NULL);
    }
    for (i = 0; HUB_COMMANDS[i].verb; i++) {
        snprintf(cmd, sizeof(cmd), "/%s", HUB_COMMANDS[i].verb);
        weechat_hook_command_run(cmd, &command_run_cb, HUB_COMMANDS[i].verb, NULL);
    }
    timer_hook = weechat_hook_timer(250, 0, 0, &timer_cb, NULL, NULL);
    weechat_hook_signal("rrc_input_send", &input_send_signal_cb, NULL, NULL);
    weechat_hook_info("rrc_max_body", "largest message body (bytes) that fits a room now",
                      "server,room", &info_cb, NULL, NULL);
    weechat_hook_info("rrc_queue", "RRC messages waiting for the hub's rate limit",
                      "server", &info_cb, NULL, NULL);

    for (s = servers; s; s = s->next)
        if (server_bool(s->name, "autoconnect"))
            server_connect(s);
    return WEECHAT_RC_OK;
}

int
weechat_plugin_end(struct t_weechat_plugin *plugin)
{
    while (servers)
        server_free(servers);
    if (timer_hook)
        weechat_unhook(timer_hook);
    if (config_file) {
        weechat_config_write(config_file);
        weechat_config_free(config_file);
    }
    memset(&identity, 0, sizeof(identity));
    identity_loaded = 0;
    return WEECHAT_RC_OK;
}
