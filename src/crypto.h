/*
 * crypto.h - the primitives Reticulum uses, on top of OpenSSL libcrypto
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_CRYPTO_H
#define RRC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CR_SHA256_LEN 32
#define CR_X25519_LEN 32
#define CR_ED25519_LEN 32
#define CR_SIG_LEN 64

/* A Reticulum token: IV(16) + AES-256-CBC ciphertext + HMAC-SHA256(32). */
#define CR_TOKEN_OVERHEAD 48
#define CR_TOKEN_KEY_LEN 64

int cr_random(uint8_t *out, size_t len);

void cr_sha256(const uint8_t *data, size_t len, uint8_t out[CR_SHA256_LEN]);
void cr_sha256_2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                 uint8_t out[CR_SHA256_LEN]);
void cr_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len, uint8_t out[CR_SHA256_LEN]);
/* RFC 5869 HKDF-SHA256. An empty salt means 32 zero bytes, as in RNS. */
void cr_hkdf(const uint8_t *ikm, size_t ikm_len,
             const uint8_t *salt, size_t salt_len,
             const uint8_t *info, size_t info_len,
             uint8_t *out, size_t out_len);

int cr_x25519_public(const uint8_t prv[CR_X25519_LEN], uint8_t pub[CR_X25519_LEN]);
int cr_x25519_shared(const uint8_t prv[CR_X25519_LEN], const uint8_t peer[CR_X25519_LEN],
                     uint8_t out[CR_X25519_LEN]);

int cr_ed25519_public(const uint8_t seed[CR_ED25519_LEN], uint8_t pub[CR_ED25519_LEN]);
int cr_ed25519_sign(const uint8_t seed[CR_ED25519_LEN], const uint8_t *msg, size_t len,
                    uint8_t sig[CR_SIG_LEN]);
/* Returns 1 for a valid signature, 0 otherwise. */
int cr_ed25519_verify(const uint8_t pub[CR_ED25519_LEN], const uint8_t *msg, size_t len,
                      const uint8_t sig[CR_SIG_LEN]);

/* Token encrypt: out must hold len + 16 (padding) + CR_TOKEN_OVERHEAD bytes.
 * Returns the token length, or -1. */
long cr_token_encrypt(const uint8_t key[CR_TOKEN_KEY_LEN], const uint8_t *iv_or_null,
                      const uint8_t *in, size_t len, uint8_t *out);
/* Token decrypt: verifies the HMAC first. out must hold len bytes.
 * Returns the plaintext length, or -1. */
long cr_token_decrypt(const uint8_t key[CR_TOKEN_KEY_LEN],
                      const uint8_t *in, size_t len, uint8_t *out);

void cr_wipe(void *p, size_t len);

#endif
