
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "spake2.h"

int main(void)
{
    int ret;

    if (sodium_init() != 0) {
        return 1;
    }

    unsigned char stored_data[crypto_spake_STOREDBYTES];
    ret = crypto_spake_server_store(stored_data, "test", 4,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE);
    assert(ret == 0);

    unsigned char public_data[crypto_spake_PUBLICDATABYTES];
    crypto_spake_server_state server_st;
    ret = crypto_spake_step0(&server_st, public_data, stored_data);
    assert(ret == 0);

    crypto_spake_client_state client_st;

    unsigned char response1[crypto_spake_RESPONSE1BYTES];
    ret = crypto_spake_step1(&client_st, response1, public_data, "test", 4);
    assert(ret == 0);

    unsigned char response2[crypto_spake_RESPONSE2BYTES];
    crypto_spake_shared_keys shared_keys_from_client;
    ret = crypto_spake_step2(&server_st, response2, &shared_keys_from_client,
                             "alice", 5, "bob", 3, stored_data, response1);
    assert(ret == 0);

    unsigned char response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_shared_keys shared_keys_from_server;
    ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                             "alice", 5, "bob", 3, response2);
    assert(ret == 0);

    ret = crypto_spake_step4(&server_st, response3);
    assert(ret == 0);

    assert(memcmp(&shared_keys_from_client, &shared_keys_from_server,
                  sizeof shared_keys_from_client) == 0);

    return 0;
}
