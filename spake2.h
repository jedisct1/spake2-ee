
#define crypto_spake_STOREDBYTES 132
#define crypto_spake_PUBLICDATABYTES 36
#define crypto_spake_RESPONSE1BYTES 32
#define crypto_spake_RESPONSE2BYTES 64
#define crypto_spake_RESPONSE3BYTES 32

typedef struct crypto_spake_client_state_ {
    unsigned char h_L[32];
    unsigned char N[32];
    unsigned char x[32];
    unsigned char X[32];
} crypto_spake_client_state;

typedef struct crypto_spake_server_state_ {
    unsigned char server_validator[32];
} crypto_spake_server_state;

typedef struct crypto_spake_shared_keys_ {
    unsigned char client_sk[32];
    unsigned char server_sk[32];
} crypto_spake_shared_keys;

int crypto_spake_server_store(unsigned char stored_data[crypto_spake_STOREDBYTES],
                              const char * const passwd, unsigned long long passwdlen,
                              unsigned long long opslimit, size_t memlimit);

int crypto_spake_step0_dummy(crypto_spake_server_state *st,
                             unsigned char public_data[crypto_spake_PUBLICDATABYTES],
                             const char *client_id, size_t client_id_len,
                             const char *server_id, size_t server_id_len,
                             unsigned long long opslimit, size_t memlimit,
                             const unsigned char key[32]);

int crypto_spake_step0(crypto_spake_server_state *st,
                       unsigned char public_data[crypto_spake_PUBLICDATABYTES],
                       const unsigned char stored_data[crypto_spake_STOREDBYTES]);

int crypto_spake_step1(crypto_spake_client_state *st, unsigned char response1[crypto_spake_RESPONSE1BYTES],
                       const unsigned char public_data[crypto_spake_PUBLICDATABYTES],
                       const char * const passwd, unsigned long long passwdlen);

int crypto_spake_step2(crypto_spake_server_state *st,
                       unsigned char response2[crypto_spake_RESPONSE2BYTES],
                       crypto_spake_shared_keys *shared_keys,
                       const char *client_id, size_t client_id_len,
                       const char *server_id, size_t server_id_len,
                       const unsigned char stored_data[crypto_spake_STOREDBYTES],
                       const unsigned char response1[crypto_spake_RESPONSE1BYTES]);

int crypto_spake_step3(crypto_spake_client_state *st,
                       unsigned char response3[crypto_spake_RESPONSE3BYTES],
                       crypto_spake_shared_keys *shared_keys,
                       const char *client_id, size_t client_id_len,
                       const char *server_id, size_t server_id_len,
                       const unsigned char response2[crypto_spake_RESPONSE2BYTES]);

int crypto_spake_step4(crypto_spake_server_state *st,
                       const unsigned char response3[crypto_spake_RESPONSE3BYTES]);
