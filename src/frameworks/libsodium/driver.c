#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// from BearSSL hextobin
// not constant time, but we can filter out the results
// If libary is dynamicly linked filtering is not necessary
static size_t __attribute__((optimize("O0"))) hextobin(unsigned char *dst, const char *src)
{
    size_t num;
    unsigned acc;
    int z;

    num = 0;
    z = 0;
    acc = 0;
    while (*src != 0)
    {
        int c = *src++;
        if (c >= '0' && c <= '9')
        {
            c -= '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            c -= ('A' - 10);
        }
        else if (c >= 'a' && c <= 'f')
        {
            c -= ('a' - 10);
        }
        else
        {
            continue;
        }
        if (z)
        {
            *dst++ = (acc << 4) + c;
            num++;
        }
        else
        {
            acc = c;
        }
        z = !z;
    }
    return num;
}

int main(int argc, char *argv[])
{
    if (sodium_init() < 0)
    {
        printf("panic! the library couldn't be initialized; it is not safe to use");
        exit(-1);
    }

    if (argc != 3)
    {
        printf("Incorrect arguments given\n");
        return -1;
    }

    /* A 256 bit key in hex */
    char *key_hex = (char *)argv[1];
    size_t key_len = 32;

    unsigned char key[32];
    int len = hextobin(key, key_hex);
    if (len < 32)
    {
        printf("Insufficient key length");
        return -1;
    }

    /* The encryption primitive to use */
    char *mode = argv[2];

    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"The quick brown fox";
    size_t m_len = sizeof(plaintext);

    if (!strcmp(mode, "secretbox"))
    {
        size_t c_len = crypto_secretbox_MACBYTES + m_len;
        unsigned char nonce[32];
        unsigned char ciphertext[c_len];

        randombytes_buf(nonce, sizeof nonce);
        crypto_secretbox_easy(ciphertext, plaintext, m_len, nonce, key);

        unsigned char decrypted[m_len];
        if (crypto_secretbox_open_easy(decrypted, ciphertext, c_len, nonce, key) != 0)
        {
            printf("secretbox failed\n");
            return -1;
        }
    }
    if (!strcmp(mode, "secretstream"))
    {
        unsigned char *plaintext2 = (unsigned char *)"lorem ipsum";
        size_t m2_len = sizeof(plaintext);

        // Encryption
        crypto_secretstream_xchacha20poly1305_state state;
        unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        unsigned char c1[m_len + crypto_secretstream_xchacha20poly1305_ABYTES];
        unsigned char c2[m2_len + crypto_secretstream_xchacha20poly1305_ABYTES];

        /* Set up a new stream: initialize the state and create the header */
        crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

        /* Now, encrypt the first chunk. `c1` will contain an encrypted,
         * authenticated representation of `MESSAGE_PART1`. */
        crypto_secretstream_xchacha20poly1305_push(&state, c1, NULL, plaintext, m_len, NULL, 0, 0);

        /* Encrypt the last chunk, and store the ciphertext into `c3`.
         * Note the `TAG_FINAL` tag to indicate that this is the final chunk. */
        crypto_secretstream_xchacha20poly1305_push(&state, c2, NULL, plaintext2, m2_len, NULL, 0,
                                                   crypto_secretstream_xchacha20poly1305_TAG_FINAL);

        // Decryption
        unsigned char tag;
        unsigned char m1[m_len], m2[m2_len];

        /* Decrypt the stream: initializes the state, using the key and a header */
        if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
        {
            /* Invalid header, no need to go any further */
            printf("Invalid header, no need to go any further\n");
            return -1;
        }

        /* Decrypt the first chunk. A real application would probably use
         * a loop, that reads data from the network or from disk, and exits after
         * an error, or after the last chunk (with a `TAG_FINAL` tag) has been
         * decrypted. */
        if (crypto_secretstream_xchacha20poly1305_pull(&state, m1, NULL, &tag, c1, sizeof c1, NULL, 0) != 0)
        {
            /* Invalid/incomplete/corrupted ciphertext - abort */
            printf("Invalid/incomplete/corrupted ciphertext - abort\n");
            return -1;
        }
        assert(tag == 0); /* The tag is the one we attached to this chunk: 0 */

        /* Decrypt the second chunk, store the result into `m2` */
        if (crypto_secretstream_xchacha20poly1305_pull(&state, m2, NULL, &tag, c2, sizeof c2, NULL, 0) != 0)
        {
            /* Invalid/incomplete/corrupted ciphertext - abort */
            printf("Invalid/incomplete/corrupted ciphertext - abort\n");
            return -1;
        }
        /* The tag indicates that this is the final chunk, no need to read and decrypt more */
        assert(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    }
    if (!strcmp(mode, "generichash"))
    {
        unsigned char hash[crypto_generichash_BYTES];

        crypto_generichash(hash, sizeof hash,
                           plaintext, m_len,
                           key, sizeof key);
    }
    if (!strcmp(mode, "hmac-sha2"))
    {
        unsigned char hash[crypto_auth_hmacsha512_BYTES];

        crypto_auth_hmacsha512(hash, plaintext, m_len, key);
    }
    if (!strcmp(mode, "crypto_box"))
    {
        size_t c_len = crypto_box_MACBYTES + m_len;

        unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
        unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
        crypto_box_seed_keypair(alice_publickey, alice_secretkey, key);

        // invert key to get different keypair for bob
        for (int i = 0; i < key_len; i++)
            key[i] = ~key[i];
        unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
        unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
        crypto_box_seed_keypair(bob_publickey, bob_secretkey, key);

        unsigned char nonce[crypto_box_NONCEBYTES];
        unsigned char ciphertext[c_len];
        randombytes_buf(nonce, sizeof nonce);
        if (crypto_box_easy(ciphertext, plaintext, m_len, nonce,
                            bob_publickey, alice_secretkey) != 0)
        {
            /* error */
            printf("crypto_box error - abort\n");
            return -1;
        }

        unsigned char decrypted[m_len];
        if (crypto_box_open_easy(decrypted, ciphertext, c_len, nonce,
                                 alice_publickey, bob_secretkey) != 0)
        {
            /* message for Bob pretending to be from Alice has been forged! */
            printf("crypto_box message for Bob pretending to be from Alice has been forged!\n");
            return -1;
        }
    }
    if (!strcmp(mode, "crypto_sign"))
    {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(pk, sk, key);

        unsigned char signed_message[crypto_sign_BYTES + m_len];
        unsigned long long signed_message_len;

        crypto_sign(signed_message, &signed_message_len,
                    plaintext, m_len, sk);

        unsigned char unsigned_message[m_len];
        unsigned long long unsigned_message_len;
        if (crypto_sign_open(unsigned_message, &unsigned_message_len,
                             signed_message, signed_message_len, pk) != 0)
        {
            /* incorrect signature! */
            printf("crypto_sign incorrect signature!\n");
            return -1;
        }
    }
    if (!strcmp(mode, "crypto_seal"))
    {
        size_t c_len = crypto_box_SEALBYTES + m_len;

        /* Recipient creates a long-term key pair */
        unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
        crypto_box_seed_keypair(recipient_pk, recipient_sk, key);

        /* Anonymous sender encrypts a message using an ephemeral key pair
         * and the recipient's public key */
        unsigned char ciphertext[c_len];
        crypto_box_seal(ciphertext, plaintext, m_len, recipient_pk);

        /* Recipient decrypts the ciphertext */
        unsigned char decrypted[m_len];
        if (crypto_box_seal_open(decrypted, ciphertext, c_len,
                                 recipient_pk, recipient_sk) != 0)
        {
            /* message corrupted or not intended for this recipient */
            printf("crypt_seal message corrupted or not intended for this recipient\n");
            return -1;
        }
    }
    if (!strcmp(mode, "crypto_seal"))
    {
        unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];

        /* Generate the client's key pair */
        crypto_kx_seed_keypair(client_pk, client_sk, key);

        // invert key to get different keypair for bob
        for (int i = 0; i < key_len; i++)
            key[i] = ~key[i];

        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];

        crypto_kx_seed_keypair(server_pk, server_sk, key);

        /* Prerequisite after this point: the server's public key must be known by the client */

        /* Compute two shared keys using the server's public key and the client's secret key.
        client_rx will be used by the client to receive data from the server,
        client_tx will be used by the client to send data to the server. */
        if (crypto_kx_client_session_keys(client_rx, client_tx,
                                          client_pk, client_sk, server_pk) != 0)
        {
            printf("crypto_kx Suspicious server public key, bail out\n");
            return -1;
        }
        if (crypto_kx_server_session_keys(server_rx, server_tx,
                                          server_pk, server_sk, client_pk) != 0)
        {
            printf("crypto_kx Suspicious client public key, bail out\n");
            return -1;
        }
    }

    printf("successful\n");
    return 0;
}