
#include <string.h>
#include <sodium.h>

#include "pushpop.h"
#include "spake2.h"

typedef struct spake2_keys_ {
    unsigned char M[32];
    unsigned char N[32];
    unsigned char L[32];
    unsigned char h_L[32];
} spake2_keys;

int
_sc25519_is_canonical(const unsigned char *s)
{
    /* 2^252+27742317777372353535851937790883648493 */
    static const unsigned char L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    unsigned char c = 0;
    unsigned char n = 1;
    unsigned int  i = 32;

    do {
        i--;
        c |= ((s[i] - L[i]) >> 8) & n;
        n &= ((s[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

static void
_random_scalar(unsigned char n[32])
{
    do {
        randombytes_buf(n, 32);
        n[0] &= 248;
        n[31] &= 31;
    } while (_sc25519_is_canonical(n) == 0);
}

static int
_create_keys(spake2_keys *keys, unsigned char salt[crypto_pwhash_SALTBYTES],
             const char * const passwd, unsigned long long passwdlen,
             unsigned long long opslimit, size_t memlimit)
{
    unsigned char  h_MNL[32 * 3];
    unsigned char *h_M = &h_MNL[32 * 0];
    unsigned char *h_N = &h_MNL[32 * 1];
    unsigned char *h_L = &h_MNL[32 * 2];

    if (crypto_pwhash(h_MNL, sizeof h_MNL, passwd, passwdlen, salt,
                      opslimit, memlimit, crypto_pwhash_alg_default()) != 0) {
        return -1;
    }
    crypto_core_ed25519_from_uniform(keys->M, h_M);
    crypto_core_ed25519_from_uniform(keys->N, h_N);
    memcpy(keys->h_L, h_L, 32);
    crypto_scalarmult_ed25519_base(keys->L, keys->h_L);

    return 0;
}

static int
crypto_spake_server_store(unsigned char stored_data[132],
                          const char * const passwd,
                          unsigned long long passwdlen,
                          unsigned long long opslimit, size_t memlimit)
{
    spake2_keys   keys;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    size_t        i;

    randombytes_buf(salt, sizeof salt);
    if (_create_keys(&keys, salt, passwd, passwdlen, opslimit, memlimit) != 0) {
        return -1;
    }
    i = 0;
    _push16 (stored_data, &i, 0x0001);
    _push16 (stored_data, &i, crypto_pwhash_alg_default());
    _push64 (stored_data, &i, (uint64_t) opslimit);
    _push64 (stored_data, &i, (uint64_t) memlimit);
    _push128(stored_data, &i, salt);
    _push256(stored_data, &i, keys.M);
    _push256(stored_data, &i, keys.N);
    _push256(stored_data, &i, keys.L);

    return 0;
}

static int
crypto_spake_server_public_data(unsigned char public_data[36],
                                const unsigned char stored_data[132])
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    size_t        i, j;
    uint16_t      v16;
    uint64_t      v64;

    i = 0;
    j = 0;
    _pop16 (&v16, stored_data, &i); /* version */
    if (v16 != 0x0001) {
        return -1;
    }
    _push16(public_data, &j, v16);
    _pop16 (&v16, stored_data, &i); /* alg */
    _push16(public_data, &j, v16);
    _pop64 (&v64, stored_data, &i); /* opslimit */
    _push64(public_data, &j, v64);
    _pop64 (&v64, stored_data, &i); /* memlimit */
    _push64(public_data, &j, v64);
    _pop128(salt, stored_data, &i); /* salt */
    _push128(public_data, &j, salt);

    return 0;
}

static int
crypto_spake_client_init(crypto_spake_client_state *st,
                         unsigned char X[32],
                         const unsigned char public_data[36],
                         const char * const passwd,
                         unsigned long long passwdlen)
{
    spake2_keys        keys;
    unsigned char      x[32];
    unsigned char      gx[32];
    unsigned char      salt[crypto_pwhash_SALTBYTES];
    size_t             i;
    int                alg;
    unsigned long long opslimit;
    size_t             memlimit;
    uint16_t           v16;
    uint64_t           v64;

    i = 0;
    _pop16 (&v16, public_data, &i);
    if (v16 != 0x0001) {
        return -1;
    }
    _pop16 (&v16, public_data, &i); /* alg */
    alg = (int) v16;
    _pop64 (&v64, public_data, &i); /* opslimit */
    opslimit = (unsigned long long) v64;
    _pop64 (&v64, public_data, &i); /* memlimit */
    memlimit = (size_t) v64;
    _pop128(salt, public_data, &i); /* salt */
    if (_create_keys(&keys, salt, passwd, passwdlen, opslimit, memlimit) != 0) {
        return -1;
    }
    _random_scalar(x);
    crypto_scalarmult_ed25519_base(gx, x);
    crypto_core_ed25519_add(X, gx, keys.M);

    memcpy(st->h_L, keys.h_L, 32);
    memcpy(st->N, keys.N, 32);
    memcpy(st->x, x, 32);
    memcpy(st->X, X, 32);

    return 0;
}

static int
_shared_keys(crypto_spake_client_shared_keys *shared_keys,
             const char *client_id, size_t client_id_len,
             const char *server_id, size_t server_id_len,
             const unsigned char X[32], const unsigned char Y[32],
             const unsigned char Z[32], const unsigned char V[32])
{
    crypto_generichash_state st;
    unsigned char            len;
    unsigned char            k0[crypto_kdf_KEYBYTES];

    if (client_id_len > 255 || server_id_len > 255) {
        return -1;
    }
    crypto_generichash_init(&st, NULL, 0, sizeof k0);
    len = (unsigned char) client_id_len;
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, (const unsigned char *) client_id, len);
    len = (unsigned char) server_id_len;
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, (const unsigned char *) server_id, len);
    len = 32;
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, X, len);
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, Y, len);
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, Z, len);
    crypto_generichash_update(&st, &len, 1);
    crypto_generichash_update(&st, V, len);
    crypto_generichash_final(&st, k0, sizeof k0);

    crypto_kdf_derive_from_key(shared_keys->client_sk, 32, 0, "PAKE2+EE", k0);
    crypto_kdf_derive_from_key(shared_keys->server_sk, 32, 1, "PAKE2+EE", k0);
    crypto_kdf_derive_from_key(shared_keys->client_validator, 32, 2, "PAKE2+EE", k0);
    crypto_kdf_derive_from_key(shared_keys->server_validator, 32, 3, "PAKE2+EE", k0);

    sodium_memzero(k0, sizeof k0);

    return 0;
}

int
crypto_spake_server_init(unsigned char Y[32],
                         crypto_spake_client_shared_keys *shared_keys,
                         const char *client_id, size_t client_id_len,
                         const char *server_id, size_t server_id_len,
                         const unsigned char stored_data[132],
                         const unsigned char X[32])
{
    spake2_keys        keys;
    unsigned char      gx[32];
    unsigned char      gy[32];
    unsigned char      V[32];
    unsigned char      Z[32];
    unsigned char      salt[crypto_pwhash_SALTBYTES];
    unsigned char      y[32];
    size_t             i;
    uint16_t           v16;
    uint64_t           v64;

    i = 0;
    _pop16 (&v16, stored_data, &i); /* version */
    if (v16 != 0x0001) {
        return -1;
    }
    _pop16 (&v16, stored_data, &i); /* alg */
    _pop64 (&v64, stored_data, &i); /* opslimit */
    _pop64 (&v64, stored_data, &i); /* memlimit */
    _pop128(salt, stored_data, &i); /* salt */
    _pop256(keys.M, stored_data, &i);
    _pop256(keys.N, stored_data, &i);
    _pop256(keys.L, stored_data, &i);

    _random_scalar(y);
    crypto_scalarmult_ed25519_base(gy, y);
    crypto_core_ed25519_add(Y, gy, keys.N);

    crypto_core_ed25519_sub(gx, X, keys.M);
    if (crypto_scalarmult_ed25519(Z, y, gx) != 0) {
        return -1;
    }
    if (crypto_scalarmult_ed25519(V, y, keys.L) != 0) {
        return -1;
    }
    if (_shared_keys(shared_keys, client_id, client_id_len,
                     server_id, server_id_len, X, Y, Z, V) != 0) {
        return -1;
    }
    return 0;
}

int
crypto_spake_client_response(crypto_spake_client_state *st,
                             crypto_spake_client_shared_keys *shared_keys,
                             const char *client_id, size_t client_id_len,
                             const char *server_id, size_t server_id_len,
                             const unsigned char Y[32])
{
    unsigned char gy[32];
    unsigned char V[32];
    unsigned char Z[32];

    crypto_core_ed25519_sub(gy, Y, st->N);
    if (crypto_scalarmult_ed25519(Z, st->x, gy) != 0) {
        return -1;
    }
    if (crypto_scalarmult_ed25519(V, st->h_L, gy) != 0) {
        return -1;
    }
    if (_shared_keys(shared_keys, client_id, client_id_len,
                     server_id, server_id_len, st->X, Y, Z, V) != 0) {
        return -1;
    }
    return 0;
}

