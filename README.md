# SPAKE2+EE

A SPAKE2+EE (SPAKE2+ Elligator Edition) implementation for libsodium 1.0.16+

## Blurb

SPAKE2 is a password-authenticated key agreement protocol, allowing two parties
that share a password to securely authenticate each other and derive ephemeral
session keys. It is computationally efficient, and has a strong security proof.

This is an implementation of the
[SPAKE2+EE](https://moderncrypto.org/mail-archive/curves/2015/000424.html)
variant. It's slightly faster than the original SPAKE2 and has better security
assumptions. It is also augmented, meaning that even if the credentials stored
on the server ever get leaked, this would not be sufficient to log in.

## Usage

The SPAKE2 protocol only requires one round trip to derive shared keys, and
another round trip for mutual authentication.

```c
    /* A client identifier (username, email address, public key...) */
    #define CLIENT_ID "client"

    /* A server identifier (IP address, host name, public key...) */
    #define SERVER_ID "server"


    /*
     * Computes a blob to be stored by the server, using the default
     * libsodium password hashing function (currently Argon2id) and
     * parameters. This operation can also be performed by the
     * client, with the result eventually sent to the server over a
     * secure channel.
     */

    unsigned char stored_data[crypto_spake_STOREDBYTES];
    ret = crypto_spake_server_store(stored_data, "test", 4,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE);
    assert(ret == 0);


    /*
     * `public data` is a subset of the data stored on the server.
     * It only contains the parameters of the password hashing function.
     */

    unsigned char public_data[crypto_spake_PUBLICDATABYTES];
    crypto_spake_server_state server_st;
    ret = crypto_spake_step0(&server_st, public_data, stored_data);
    assert(ret == 0);


    /*
     * [CLIENT SIDE]
     * Computes a packet `response1` using `public_data` and the password.
     * This first packet has to be sent to the server.
     */

    crypto_spake_client_state client_st;
    unsigned char response1[crypto_spake_RESPONSE1BYTES];
    ret = crypto_spake_step1(&client_st, response1, public_data, "test", 4);
    assert(ret == 0);


    /*
     * [SERVER SIDE]
     * Processes `response1` received from the client.
     * Returns `response2` to be sent to the client.
     */

    unsigned char response2[crypto_spake_RESPONSE2BYTES];
    crypto_spake_shared_keys shared_keys_from_client;
    ret = crypto_spake_step2(&server_st, response2,
                             CLIENT_ID, sizeof CLIENT_ID - 1,
                             SERVER_ID, sizeof SERVER_ID - 1,
                             stored_data, response1);
    assert(ret == 0);


    /*
     * [CLIENT SIDE]
     * Processes `response2` received from the server.
     * Returns a set of shared keys in `shared_keys_from_server`,
     * as well as `response3` to be sent to the server for validation.
     */

    unsigned char response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_shared_keys shared_keys_from_server;
    ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                             CLIENT_ID, sizeof CLIENT_ID - 1,
                             SERVER_ID, sizeof SERVER_ID - 1, response2);
    assert(ret == 0);


    /*
     * [SERVER SIDE]
     * Processes `response3` received from the client.
     * After validation, returns a set of shared key (identical to the one
     * computed by the client) in `shared_keys_from_client`.
     */

    ret = crypto_spake_step4(&server_st, &shared_keys_from_client, response3);
    assert(ret == 0);


    /*
     * Both parties now share two session keys.
     * The first one can be used for server->client communications,
     * and the second one can be used in the other direction.
     */

    assert(memcmp(&shared_keys_from_client, &shared_keys_from_server,
                  sizeof shared_keys_from_client) == 0);
```
