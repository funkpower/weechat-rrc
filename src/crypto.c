/*
 * crypto.c - the primitives Reticulum uses, on top of OpenSSL libcrypto
 *
 * Only APIs present in both OpenSSL 1.1.1 and 3.x are used, so the plugin
 * builds on Debian 12 (3.0) and on rolling distributions alike.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto.h"

int
cr_random(uint8_t *out, size_t len)
{
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

void
cr_wipe(void *p, size_t len)
{
    OPENSSL_cleanse(p, len);
}

void
cr_sha256(const uint8_t *data, size_t len, uint8_t out[CR_SHA256_LEN])
{
    unsigned int out_len = CR_SHA256_LEN;
    EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL);
}

void
cr_sha256_2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
            uint8_t out[CR_SHA256_LEN])
{
    unsigned int out_len = CR_SHA256_LEN;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (alen)
        EVP_DigestUpdate(ctx, a, alen);
    if (blen)
        EVP_DigestUpdate(ctx, b, blen);
    EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);
}

void
cr_hmac_sha256(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t len, uint8_t out[CR_SHA256_LEN])
{
    uint8_t k[64], pad[64], inner[CR_SHA256_LEN];
    unsigned int out_len = CR_SHA256_LEN;
    EVP_MD_CTX *ctx;
    int i;

    memset(k, 0, sizeof(k));
    if (key_len > sizeof(k))
        cr_sha256(key, key_len, k);
    else if (key_len)
        memcpy(k, key, key_len);

    ctx = EVP_MD_CTX_new();
    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x36;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pad, 64);
    if (len)
        EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, inner, &out_len);

    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x5c;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pad, 64);
    EVP_DigestUpdate(ctx, inner, sizeof(inner));
    out_len = CR_SHA256_LEN;
    EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);

    cr_wipe(k, sizeof(k));
    cr_wipe(pad, sizeof(pad));
}

void
cr_hkdf(const uint8_t *ikm, size_t ikm_len,
        const uint8_t *salt, size_t salt_len,
        const uint8_t *info, size_t info_len,
        uint8_t *out, size_t out_len)
{
    static const uint8_t zero_salt[CR_SHA256_LEN] = { 0 };
    uint8_t prk[CR_SHA256_LEN], block[CR_SHA256_LEN];
    uint8_t buf[CR_SHA256_LEN + 256 + 1];
    size_t done = 0, block_len = 0, n;
    uint8_t counter = 1;

    if (!salt || !salt_len) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    if (info_len > 256)
        info_len = 256;
    cr_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    while (done < out_len) {
        n = 0;
        memcpy(buf, block, block_len);
        n += block_len;
        if (info_len) {
            memcpy(buf + n, info, info_len);
            n += info_len;
        }
        buf[n++] = counter++;
        cr_hmac_sha256(prk, sizeof(prk), buf, n, block);
        block_len = sizeof(block);
        n = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, n);
        done += n;
    }
    cr_wipe(prk, sizeof(prk));
    cr_wipe(block, sizeof(block));
    cr_wipe(buf, sizeof(buf));
}

int
cr_x25519_public(const uint8_t prv[CR_X25519_LEN], uint8_t pub[CR_X25519_LEN])
{
    EVP_PKEY *key;
    size_t len = CR_X25519_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, prv, CR_X25519_LEN);
    if (key && EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == CR_X25519_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    return rc;
}

int
cr_x25519_shared(const uint8_t prv[CR_X25519_LEN], const uint8_t peer[CR_X25519_LEN],
                 uint8_t out[CR_X25519_LEN])
{
    EVP_PKEY *key, *peer_key;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = CR_X25519_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, prv, CR_X25519_LEN);
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, CR_X25519_LEN);
    if (!key || !peer_key)
        goto end;
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1
        || EVP_PKEY_derive_set_peer(ctx, peer_key) != 1
        || EVP_PKEY_derive(ctx, out, &len) != 1 || len != CR_X25519_LEN)
        goto end;
    rc = 0;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_free(peer_key);
    return rc;
}

int
cr_ed25519_public(const uint8_t seed[CR_ED25519_LEN], uint8_t pub[CR_ED25519_LEN])
{
    EVP_PKEY *key;
    size_t len = CR_ED25519_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, CR_ED25519_LEN);
    if (key && EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == CR_ED25519_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    return rc;
}

int
cr_ed25519_sign(const uint8_t seed[CR_ED25519_LEN], const uint8_t *msg, size_t len,
                uint8_t sig[CR_SIG_LEN])
{
    EVP_PKEY *key;
    EVP_MD_CTX *ctx = NULL;
    size_t sig_len = CR_SIG_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, CR_ED25519_LEN);
    if (!key)
        goto end;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1
        || EVP_DigestSign(ctx, sig, &sig_len, msg, len) != 1 || sig_len != CR_SIG_LEN)
        goto end;
    rc = 0;
end:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

int
cr_ed25519_verify(const uint8_t pub[CR_ED25519_LEN], const uint8_t *msg, size_t len,
                  const uint8_t sig[CR_SIG_LEN])
{
    EVP_PKEY *key;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, CR_ED25519_LEN);
    if (!key)
        goto end;
    ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1
        && EVP_DigestVerify(ctx, sig, CR_SIG_LEN, msg, len) == 1)
        ok = 1;
end:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

long
cr_token_encrypt(const uint8_t key[CR_TOKEN_KEY_LEN], const uint8_t *iv_or_null,
                 const uint8_t *in, size_t len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int n1 = 0, n2 = 0;
    long total = -1;

    if (iv_or_null)
        memcpy(out, iv_or_null, 16);
    else if (cr_random(out, 16) != 0)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key + 32, out) == 1
        && EVP_EncryptUpdate(ctx, out + 16, &n1, in, (int)len) == 1
        && EVP_EncryptFinal_ex(ctx, out + 16 + n1, &n2) == 1) {
        total = 16 + n1 + n2;
        cr_hmac_sha256(key, 32, out, (size_t)total, out + total);
        total += CR_SHA256_LEN;
    }
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

long
cr_token_decrypt(const uint8_t key[CR_TOKEN_KEY_LEN],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t mac[CR_SHA256_LEN];
    EVP_CIPHER_CTX *ctx;
    size_t ct_len;
    int n1 = 0, n2 = 0;
    long total = -1;

    /* IV + at least one AES block + HMAC */
    if (len < 16 + 16 + CR_SHA256_LEN)
        return -1;
    ct_len = len - 16 - CR_SHA256_LEN;
    if (ct_len % 16)
        return -1;
    cr_hmac_sha256(key, 32, in, len - CR_SHA256_LEN, mac);
    if (CRYPTO_memcmp(mac, in + len - CR_SHA256_LEN, CR_SHA256_LEN) != 0)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key + 32, in) == 1
        && EVP_DecryptUpdate(ctx, out, &n1, in + 16, (int)ct_len) == 1
        && EVP_DecryptFinal_ex(ctx, out + n1, &n2) == 1)
        total = n1 + n2;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}
