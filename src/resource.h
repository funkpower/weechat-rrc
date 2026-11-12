/*
 * resource.h - receiving Reticulum resources on the link
 *
 * A hub sends what doesn't fit one packet (a long MOTD) as an RNS Resource:
 * an advertisement, then parts we request a window at a time, the whole
 * encrypted once with the link key and optionally bz2-compressed. This is
 * the receiving half of RNS Resource.py, for single-segment resources up to
 * RNS_RESOURCE_MAX bytes; anything else is rejected so the hub stops
 * advertising it.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_RESOURCE_H
#define RRC_RESOURCE_H

#include <stddef.h>
#include <stdint.h>

#include "rns.h"

/* Largest resource we take, in data bytes (rrcd's own limit). */
#ifndef RNS_RESOURCE_MAX
#define RNS_RESOURCE_MAX (256 * 1024)
#endif

#define RNS_RES_HASH_LEN 32
#define RNS_RES_RANDOM_LEN 4
#define RNS_RES_MAPHASH_LEN 4
/* map hashes per advertisement or hashmap update: (Link.MDU - 134) / 4 */
#define RNS_RES_HASHMAP_MAX_LEN 74

/* advertisement flags */
#define RNS_RES_F_ENCRYPTED 0x01
#define RNS_RES_F_COMPRESSED 0x02
#define RNS_RES_F_SPLIT 0x04
#define RNS_RES_F_REQUEST 0x08
#define RNS_RES_F_RESPONSE 0x10
#define RNS_RES_F_METADATA 0x20

/* A resource advertisement (ResourceAdvertisement.pack(), msgpack). */
struct rns_adv {
    uint64_t t;         /* transfer size: the encrypted stream */
    uint64_t d;         /* data size */
    uint64_t n;         /* parts */
    uint64_t i, l;      /* segment index, total segments */
    uint64_t f;         /* flags */
    uint8_t h[RNS_RES_HASH_LEN];
    uint8_t r[RNS_RES_RANDOM_LEN];
    uint8_t o[RNS_RES_HASH_LEN];
    const uint8_t *m;   /* map hashes, into the input */
    size_t m_len;
    int has_q;          /* a request id: part of a request or response */
};

/* Returns 0, or -1 for anything RNS would not unpack. */
int rns_adv_unpack(const uint8_t *buf, size_t len, struct rns_adv *adv);
/* A hashmap update after its 32-byte resource hash: msgpack [segment, map]. */
int rns_hmu_unpack(const uint8_t *buf, size_t len, uint64_t *segment,
                   const uint8_t **map, size_t *map_len);

/* Turn the received stream into the resource data as Resource.assemble():
 * decrypt with the link key (when flagged), drop the random prefix,
 * decompress (when flagged, at most RNS_RESOURCE_MAX bytes) and check
 * SHA-256(data + random_hash) against the resource hash. On success *out
 * is malloc()ed and holds *out_len bytes. Returns 0, or -1. */
int rns_resource_decode(const uint8_t key[64], uint64_t flags,
                        const uint8_t *stream, size_t len,
                        const uint8_t random_hash[RNS_RES_RANDOM_LEN],
                        const uint8_t hash[RNS_RES_HASH_LEN],
                        uint8_t **out, size_t *out_len);

/* ---- used by rns.c ---- */

void rns_resource_advertised(struct rns_client *c, const uint8_t *plain, size_t len, double now);
void rns_resource_part(struct rns_client *c, const uint8_t *data, size_t len, double now);
void rns_resource_hmu(struct rns_client *c, const uint8_t *plain, size_t len, double now);
void rns_resource_cancelled(struct rns_client *c, const uint8_t *plain, size_t len);
void rns_resource_tick(struct rns_client *c, double now);
void rns_resource_free(struct rns_client *c);

/* in rns.c: send one packet on the link */
int rns_link_packet(struct rns_client *c, int packet_type, uint8_t context,
                    const uint8_t *data, size_t len, int encrypt, double now);

#endif
