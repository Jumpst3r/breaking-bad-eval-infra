
#define Lib_IntVector_Intrinsics_vec128 void *
#define Lib_IntVector_Intrinsics_vec256 void *
#define HACL_CAN_COMPILE_UINT128 1
#define LINUX_NO_EXPLICIT_BZERO

#include "Hacl_Chacha20Poly1305_32.h"

#include "Hacl_HMAC.h"
#include "Hacl_Hash_SHA1.h"
#include "Hacl_Hash_SHA2.h"
#include "Hacl_Hash_SHA3.h"
#include "Hacl_Hash_MD5.h"
#include "Hacl_Hash_Blake2.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_P256.h"
#include "Hacl_RSAPSS.h"

// from BearSSL hextobin
// not constant time, but we can filter out the results
static size_t hextobin(unsigned char *dst, const char *src)
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
    /*
     * Set up the key and iv. Do we need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key in hex */
    char *key_hex = (char *)argv[1];
    uint32_t key_len = 32;

    uint8_t key[32];
    int len = hextobin(key, key_hex);
    // if (len < 32)
    // {
    //     return -1;
    // }

    /* The encryption primitive to use */
    char *mode = argv[2];

    /* A 128 bit IV */
    uint8_t *iv = (uint8_t *)"0123456789012345678912345678912";

    /* Message to be encrypted */
    uint8_t *plaintext = (uint8_t *)"The quick brown fox";
    uint32_t m_len = sizeof(plaintext);

    /* Authenticated message */
    uint8_t *aad = (uint8_t *)"Lorem ipsum";
    uint32_t aad_len = sizeof(aad);

    /* Ciphertext buffer */
    uint8_t cipher[1024];

    /* MAC buffer */
    uint8_t mac[16];

    /* Output buffer */
    uint8_t output[1024];

    if (!strcmp(mode, "chacha_poly1305"))
    {
        Hacl_Chacha20Poly1305_32_aead_encrypt(key, iv, aad_len, aad, m_len, plaintext, cipher, mac);

        uint32_t res = Hacl_Chacha20Poly1305_32_aead_decrypt(key, iv, aad_len, aad, m_len, output, cipher, mac);
        if (res != 0)
        {
            printf("Decrypt did not work");
            return -1;
        }
    }
    else if (!strcmp(mode, "MD5"))
    {
        Hacl_Streaming_MD5_legacy_hash(key, key_len, output);
    }
    else if (!strcmp(mode, "SHA1"))
    {
        Hacl_Streaming_SHA1_legacy_hash(key, key_len, output);
    }
    else if (!strcmp(mode, "SHA2"))
    {
        // Hacl_Streaming_SHA2_hash_256(key, key_len, output);
        // Hacl_Streaming_SHA2_hash_384(key, key_len, output);
        // Hacl_Streaming_SHA2_hash_512(key, key_len, output);
        Hacl_Hash_SHA2_hash_256(key, key_len, output);
        Hacl_Hash_SHA2_hash_384(key, key_len, output);
        Hacl_Hash_SHA2_hash_512(key, key_len, output);
    }
    else if (!strcmp(mode, "SHA3"))
    {
        Hacl_SHA3_sha3_224(key_len, key, output);
        Hacl_SHA3_sha3_256(key_len, key, output);
        Hacl_SHA3_sha3_384(key_len, key, output);
        Hacl_SHA3_sha3_512(key_len, key, output);
    }
    else if (!strcmp(mode, "Blake2"))
    {
        Hacl_Blake2b_32_blake2b(64, output, m_len, plaintext, key_len, key);
        Hacl_Blake2s_32_blake2s(64, output, m_len, plaintext, key_len, key);
    }
    else if (!strcmp(mode, "hmac-sha1"))
    {
        Hacl_HMAC_legacy_compute_sha1(output, key, key_len, plaintext, m_len);
    }
    else if (!strcmp(mode, "hmac-sha2"))
    {
        Hacl_HMAC_compute_sha2_256(output, key, key_len, plaintext, m_len);
        Hacl_HMAC_compute_sha2_384(cipher, key, key_len, output, m_len);
        Hacl_HMAC_compute_sha2_512(output, key, key_len, cipher, m_len);
    }
    else if (!strcmp(mode, "hmac-blake2"))
    {
        Hacl_HMAC_compute_blake2s_32(cipher, key, key_len, plaintext, m_len);
        Hacl_HMAC_compute_blake2b_32(output, key, key_len, cipher, m_len);
    }
    else if (!strcmp(mode, "ecdh-curve25519"))
    {
        // use a hardcoded public key
        uint8_t *const_key = (uint8_t *)"dde19308ba7a7ec42e483146a1cb479b5fd164c660bd6dfbf768520f06293b26";
        uint8_t pub[32];
        Hacl_Curve25519_51_secret_to_public(pub, const_key);

        // perform ecdh with hardcoded public key
        if (!Hacl_Curve25519_51_ecdh(output, key, pub))
        {
            printf("could not perform ecdh");
            return -1;
        }
    }
    else if (!strcmp(mode, "ecdh-p256"))
    {
        // use a hardcoded public key
        uint8_t *const_key = (uint8_t *)"dde19308ba7a7ec42e483146a1cb479b5fd164c660bd6dfbf768520f06293b26";
        uint8_t pub[64];
        if (!Hacl_P256_validate_private_key(const_key))
        {
            printf("const key not valid");
            return -1;
        }
        if (!Hacl_P256_validate_private_key(key))
        {
            printf("key not valid");
            return -1;
        }
        if (!Hacl_P256_dh_initiator(pub, const_key))
        {
            printf("could not generate public key");
            return -1;
        }

        // perform ecdh with hardcoded public key
        if (!Hacl_P256_dh_responder(output, pub, key))
        {
            printf("could not perform ecdh");
            return -1;
        }
    }
    else if (!strcmp(mode, "ecdsa-p256"))
    {
        if (!Hacl_P256_validate_private_key(key))
        {
            printf("key not valid");
            return -1;
        }
        uint8_t sig[64];
        if (!Hacl_P256_ecdsa_sign_p256_sha2(sig, m_len, plaintext, key, iv))
        {
            printf("Could not create ecdsa signature\n");
            return -1;
        }
        // uint8_t pub[64];
        // if (!Hacl_P256_dh_initiator(pub, key))
        // {
        //     printf("could not generate public key");
        //     return -1;
        // }

        // if (!Hacl_P256_ecdsa_verif_p256_sha2(m_len, plaintext, pub, ))
    }
    else if (!strcmp(mode, "rsa"))
    {
        FILE *ptr;

        unsigned char buf[3 * 64];
        ptr = fopen(key_hex, "rb");
        fread(buf, sizeof(buf), 1, ptr);

        fclose(ptr);

        uint8_t *n = (uint8_t *)(buf);
        uint8_t *e = (uint8_t *)(buf + 64);
        uint8_t *d = (uint8_t *)(buf + 128);

        // printf("n = ");
        // for (int i = 0; i < 64; i++) 
        //     printf("%02x", n[i]);
        // printf("\ne = ");
        // for (int i = 0; i < 64; i++) 
        //     printf("%02x", e[i]);
        // printf("\nd = ");
        // for (int i = 0; i < 64; i++) 
        //     printf("%02x", d[i]);
        // printf("\n");

        uint32_t nb = 64, ne = 64, nd = 64;

        size_t i = 0;
        while (i < 64 && nb > 0 && n[i++] == 0)
            nb--;
        // printf("nb = %d\n", nb);
        n += 64-nb;
        int s = 7;
        nb *= 8;
        while((n[0] & (1 << s--)) == 0)
            nb--;

        i = 0;
        while (ne > 0 && e[i++] == 0)
            ne--;
        // printf("ne = %d\n", ne);
        e += 64-ne;
        s = 7;
        ne *= 8;
        while(((e[0] >> s--) & 1) == 0)
            ne--;

        i = 0;
        while (nd > 0 && d[i++] == 0)
            nd--;
        // printf("nd = %d\n", nd);
        s = 7;
        nd *= 8;
        while(((d[0] >> s--) & 1) == 0)
            nd--;

        // printf("nb = %d\nne = %d\nnd = %d\n", nb, ne, nd);

        uint64_t *rsa_key = Hacl_RSAPSS_new_rsapss_load_skey(nb, ne, nd, n, e, d);
        if (rsa_key == NULL) {
            printf("Could not import RSA skey\n");
            return -1;
        }

        // printf("imported skey\n");
        uint8_t sig[64];
        if (!Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, nb, ne, nd, rsa_key, sizeof(iv), iv, m_len, plaintext, sig))
        {
            printf("Could not create ecdsa signature\n");
            return -1;
        }
    }
    else
    {
        return -1;
    }

    return 0;
}
