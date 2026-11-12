/*
 * rns.h - a minimal Reticulum client: one identity, one link to one
 * destination, over one interface (a transport node or a shared instance)
 *
 * It implements just enough of Reticulum to be an RRC client: identities,
 * packets, announce validation, path requests, links (handshake, encryption,
 * identify, keepalive, teardown) and resources the destination sends. It
 * owns no sockets and no timers; the caller feeds it packets and calls
 * rns_client_tick() regularly.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_RNS_H
#define RRC_RNS_H

#include <stddef.h>
#include <stdint.h>

#define RNS_HASH_LEN 16
#define RNS_NAME_HASH_LEN 10
#define RNS_PUBKEY_LEN 64
#define RNS_PRVKEY_LEN 64
#define RNS_MTU 500
#define RNS_HEADER_MINSIZE 19   /* 2 + 1 + 16 */
#define RNS_HEADER_MAXSIZE 35   /* 2 + 1 + 32 */
/* floor((500 - 1 - 19 - 48) / 16) * 16 - 1 */
#define RNS_LINK_MDU 431

/* packet types */
#define RNS_PT_DATA 0x00
#define RNS_PT_ANNOUNCE 0x01
#define RNS_PT_LINKREQUEST 0x02
#define RNS_PT_PROOF 0x03

/* destination types */
#define RNS_DT_SINGLE 0x00
#define RNS_DT_GROUP 0x01
#define RNS_DT_PLAIN 0x02
#define RNS_DT_LINK 0x03

/* contexts */
#define RNS_CTX_NONE 0x00
#define RNS_CTX_RESOURCE 0x01
#define RNS_CTX_RESOURCE_ADV 0x02
#define RNS_CTX_RESOURCE_REQ 0x03
#define RNS_CTX_RESOURCE_HMU 0x04
#define RNS_CTX_RESOURCE_PRF 0x05
#define RNS_CTX_RESOURCE_ICL 0x06
#define RNS_CTX_RESOURCE_RCL 0x07
#define RNS_CTX_PATH_RESPONSE 0x0b
#define RNS_CTX_KEEPALIVE 0xfa
#define RNS_CTX_LINKIDENTIFY 0xfb
#define RNS_CTX_LINKCLOSE 0xfc
#define RNS_CTX_LINKPROOF 0xfd
#define RNS_CTX_LRRTT 0xfe
#define RNS_CTX_LRPROOF 0xff

struct rns_identity {
    uint8_t x_prv[32];      /* X25519 private key */
    uint8_t ed_seed[32];    /* Ed25519 private key (seed) */
    uint8_t pub[RNS_PUBKEY_LEN];  /* X25519 public + Ed25519 public */
    uint8_t hash[RNS_HASH_LEN];
};

/* An identity file is the 64 private key bytes, as RNS writes them. */
int rns_identity_generate(struct rns_identity *id);
int rns_identity_from_bytes(struct rns_identity *id, const uint8_t prv[RNS_PRVKEY_LEN]);
int rns_identity_load(struct rns_identity *id, const char *path);
int rns_identity_save(const struct rns_identity *id, const char *path);

/* "app.aspect.aspect" -> 10-byte name hash and, with an identity hash,
 * the 16-byte destination hash. identity_hash may be NULL (PLAIN). */
void rns_name_hash(const char *name, uint8_t out[RNS_NAME_HASH_LEN]);
void rns_destination_hash(const char *name, const uint8_t *identity_hash,
                          uint8_t out[RNS_HASH_LEN]);

/* A parsed packet; data points into the raw buffer. */
struct rns_packet {
    uint8_t flags;
    uint8_t hops;
    int header_type;
    int context_flag;
    int transport_type;
    int dest_type;
    int packet_type;
    const uint8_t *transport_id;   /* NULL for HEADER_1 */
    const uint8_t *dest;
    uint8_t context;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *raw;
    size_t raw_len;
};

int rns_packet_parse(const uint8_t *raw, size_t len, struct rns_packet *p);
/* SHA-256 over the hashable part (flags low nibble + everything after the
 * hops byte and, for HEADER_2, the transport id). */
void rns_packet_hash(const struct rns_packet *p, uint8_t out[32]);

enum rns_state {
    RNS_IDLE = 0,
    RNS_PATH,        /* waiting for the destination's announce */
    RNS_LINKING,     /* link request sent, waiting for its proof */
    RNS_ACTIVE,
    RNS_CLOSED,
};

enum rns_loglevel { RNS_LOG_ERROR = 0, RNS_LOG_INFO, RNS_LOG_DEBUG };

struct rns_callbacks {
    /* Hand one raw packet to the interface. Returns 0 on success. */
    int (*send)(void *ctx, const uint8_t *pkt, size_t len);
    void (*state)(void *ctx, enum rns_state state, const char *reason);
    /* Decrypted payload of a DATA packet on the link. */
    void (*data)(void *ctx, const uint8_t *data, size_t len);
    void (*log)(void *ctx, int level, const char *msg);
    /* A resource the hub sent, received whole and checked against its hash
     * (may be NULL: resources are then received and dropped). */
    void (*resource)(void *ctx, const uint8_t *data, size_t len);
};

#define RNS_SEEN_MAX 256

struct rns_resource;

struct rns_client {
    struct rns_identity id;
    struct rns_callbacks cb;
    void *ctx;

    uint8_t dest_hash[RNS_HASH_LEN];
    int shared_instance;
    enum rns_state state;

    /* what the destination's announce told us */
    int have_path;
    uint8_t dest_pub[RNS_PUBKEY_LEN];
    uint8_t next_hop[RNS_HASH_LEN];
    int hops;

    double path_started;
    double path_requested;
    double path_timeout;

    /* link */
    uint8_t eph_x_prv[32];
    uint8_t eph_x_pub[32];
    uint8_t eph_ed_seed[32];
    uint8_t eph_ed_pub[32];
    uint8_t link_id[RNS_HASH_LEN];
    uint8_t key[64];
    double request_time;
    double establishment_timeout;
    double activated_at;
    double rtt;
    double keepalive;
    double stale_time;
    double last_inbound;
    double last_outbound;
    double last_keepalive;
    size_t mdu;
    int mtu;

    /* the resource being received, if any (resource.c) */
    struct rns_resource *resource;

    /* recently seen packet hashes, to drop duplicates */
    uint8_t seen[RNS_SEEN_MAX][RNS_HASH_LEN];
    size_t seen_next;
    size_t seen_count;

    uint64_t tx_packets, rx_packets;
};

/* Set up a client for the destination "dest_hash", which must be an
 * announced SINGLE destination named "dest_name" (e.g. "rrc.hub").
 * shared_instance: the interface is a local rnsd shared instance. */
void rns_client_init(struct rns_client *c, const struct rns_identity *id,
                     const uint8_t dest_hash[RNS_HASH_LEN],
                     int shared_instance,
                     const struct rns_callbacks *cb, void *ctx);
/* Start: request a path and open a link once the destination is known. */
void rns_client_start(struct rns_client *c, double now);
void rns_client_inbound(struct rns_client *c, const uint8_t *raw, size_t len, double now);
void rns_client_tick(struct rns_client *c, double now);
/* Send payload on the active link. Returns 0, or -1 (not active, too big). */
int rns_client_send(struct rns_client *c, const uint8_t *data, size_t len, double now);
/* Reveal our identity to the destination over the link. */
int rns_client_identify(struct rns_client *c, double now);
/* Tear the link down (sends LINKCLOSE when active). */
void rns_client_close(struct rns_client *c, double now, const char *reason);
/* Wipe key material. */
void rns_client_wipe(struct rns_client *c);

const char *rns_state_name(enum rns_state state);
void rns_hex(const uint8_t *in, size_t len, char *out);   /* out: 2*len+1 */
int rns_unhex(const char *in, uint8_t *out, size_t len);  /* exact length */

#endif
