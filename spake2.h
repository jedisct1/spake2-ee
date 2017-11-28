typedef struct crypto_spake_client_state_ {
    unsigned char h_L[32];
    unsigned char N[32];
    unsigned char x[32];
    unsigned char X[32];
} crypto_spake_client_state;

typedef struct crypto_spake_client_shared_keys_ {
    unsigned char client_sk[32];
    unsigned char server_sk[32];
    unsigned char client_validator[32];
    unsigned char server_validator[32];
} crypto_spake_client_shared_keys;

