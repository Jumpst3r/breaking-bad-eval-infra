/*
Adapted from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
(WolfSSL OpenSSL EVP compat mode)

Blinded targets: ECDH

*/

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "chex.h"

#include <string.h>

// DO NOT USE PRINTF
// In this special case it can lead to false positives
// Due to static linking we trace all memory regions

/*
mode 0: SHA1
mode 1: SHA256
mode 2: SHA512
*/
int hmac(const byte *key, int keysize, int mode)
{
    int ret;
    Hmac hmac;
    const byte in[32] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    const byte hash[256];
    if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0)
    {
        printf("Issue initializing hmac\n");
        exit(1);
    }

    int hash_func = -1;
    if (mode == 0)
    {
        hash_func = WC_SHA;
    }
    else if (mode == 1)
    {
        hash_func = WC_SHA256;
    }
    else if (mode == 2)
    {
        hash_func = WC_SHA512;
    }
    else
    {
        printf("Unknown hash function");
        exit(-1);
    }
    ret = wc_HmacSetKey(&hmac, hash_func, key, keysize);
    if (ret != 0)
    {
        printf("Issue with set key\n");
        exit(1);
    }

    ret = wc_HmacUpdate(&hmac, in, 32);
    if (ret != 0)
    {
        printf("Issue with update\n");
        exit(1);
    }
    ret = wc_HmacFinal(&hmac, (byte *)hash);
    if (ret != 0)
    {
        printf("Issue with hmac final\n");
        exit(1);
    }
    // printf("hmac successful");
    return ret;
}

/*
mode 0: cbc
mode 1: ctr
mode 2: gcm
*/
int encrypt_aes(Aes *ctx, const byte *key, int keysize, int dir, int mode)
{
    const byte iv[] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[32] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[32];
    byte result[32];
    byte auth_tag[16];
    int ret;
    ret = wc_AesSetKey(ctx, key, keysize, iv, dir);
    if (ret != 0)
    {
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    if (mode == 0)
    {
        ret = wc_AesCbcEncrypt(ctx, out, in, sizeof(in));
    }
    else if (mode == 1)
    {
        ret = wc_AesCtrEncrypt(ctx, out, in, sizeof(in));
    }
    else if (mode == 2)
    {
        ret = wc_AesGcmSetKey(ctx, key, keysize);
        if (ret != 0)
        {
            printf("Failed tp set gcm key: ERRNO %d\n", ret);
            return 1;
        }
        ret = wc_AesGcmEncrypt(ctx, out, in, sizeof(in), iv, sizeof(iv), auth_tag, sizeof(auth_tag), NULL, 0);
    }

    if (ret != 0)
    {
        printf("Failed to encrypt (AES): ERRNO %d\n", ret);
        exit(1);
    }

    if (mode == 0)
    {
        ret = wc_AesCbcDecrypt(ctx, result, out, sizeof(out));
    }
    else if (mode == 1)
    {
        // ret = wc_AesCtrDecrypt(ctx, result, out, sizeof(out));
        ret = 0;
    }
    else if (mode == 2)
    {
        ret = wc_AesGcmDecrypt(ctx, result, out, sizeof(out), iv, sizeof(iv), auth_tag, sizeof(auth_tag), NULL, 0);
    }

    if (ret == 0)
    {
        printf("aes successful");
    }

    return ret;
}

int encrypt_camellia(Camellia *ctx, const byte *key, int keysize)
{
    const byte iv[] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[32] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[32];
    int ret;
    ret = wc_CamelliaSetKey(ctx, key, keysize, iv);
    if (ret != 0)
    {
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    ret = wc_CamelliaCbcEncrypt(ctx, out, in, sizeof(in));
    if (ret != 0)
    {
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    return ret;
}

int x25519(byte *seed, int seed_size)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRngNonce(&rng, seed, seed_size);
    if (ret != 0)
    {
        printf("RNG init failed");
        exit(-1);
    }

    curve25519_key client_key, server_key;

    wc_curve25519_init(&client_key);
    wc_curve25519_init(&server_key);

    ret = wc_curve25519_make_key(&rng, 32, &client_key);
    if (ret != 0)
    {
        printf("could not generate key: ERRNO %d\n", ret);
        exit(-1);
    }

    ret = wc_curve25519_make_key(&rng, 32, &server_key);
    if (ret != 0)
    {
        printf("could not generate key\n");
        exit(-1);
    }

    byte sharedKey[32];
    unsigned int key_len = 32;
    ret = wc_curve25519_shared_secret(&client_key, &server_key, sharedKey, &key_len);
    if (ret != 0)
    {
        printf("could not generate shared key: ERRNO %d\n", ret);
        exit(-1);
    }

    byte priv[32];
    unsigned int privSz = 32;
    ret = wc_curve25519_export_public(&client_key, priv, &privSz);
    if (ret != 0)
    {
        printf("error exporting key: ERRNO %d\n", ret);
        exit(-1);
    }
    // printf("curve25519 successful ");

    // for(int i = 0; i < 32; i++)
    //     printf("%x", priv[i]);

    return ret;
}

/*
mode 0: p256r1
mode 1: p512r1
*/
int ecdh(byte *seed, int seed_size, int mode)
{
    WC_RNG rng;
    int ret;

    // wc_rng_new(seed, seed_size, NULL);

    ret = wc_InitRngNonce(&rng, seed, seed_size);
    if (ret != 0)
    {
        printf("RNG init failed");
        exit(-1);
    }

    ecc_key client_key, server_key;

    wc_ecc_init(&client_key);
    wc_ecc_init(&server_key);

    int curveid = 0;
    if (mode == 0)
        curveid = ECC_SECP256R1;
    else if (mode == 1)
        curveid = ECC_SECP521R1;
    else
    {
        printf("unsupported curve\n");
        exit(-1);
    }

    int keysize = wc_ecc_get_curve_size_from_id(curveid);
    ret = wc_ecc_make_key_ex(&rng, keysize, &client_key, curveid);
    if (ret != 0)
    {
        printf("could not generate key: ERRNO %d\n", ret);
        exit(-1);
    }

    ret = wc_ecc_make_key_ex(&rng, keysize, &server_key, curveid);
    if (ret != 0)
    {
        printf("could not generate key\n");
        exit(-1);
    }

    ret = wc_ecc_set_rng(&client_key, &rng);
    if (ret != 0)
    {
        printf("could not set key rng\n");
        exit(-1);
    }
    // ret = wc_ecc_set_rng(&server_key, &rng);
    // if (ret != 0)
    // {
    //     printf("could not set key rng\n");
    //     exit(-1);
    // }

    byte sharedKey[32];
    unsigned int key_len = 32;
    ret = wc_ecc_shared_secret(&client_key, &server_key, sharedKey, &key_len);
    if (ret != 0)
    {
        printf("could not generate shared key: ERRNO %d\n", ret);
        exit(-1);
    }

    // printf("ecdh successful");
    return ret;
}

int chachapoly(const byte *key, int keysize)
{
    if (keysize != 32)
    {
        printf("unsupported keysize: %d", keysize);
        exit(-1);
    }
    const byte iv[12] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[16] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[16];
    byte authtag[16];
    int ret;
    ret = wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, in, sizeof(in), out, authtag);
    if (ret != 0)
    {
        printf("Failed to encrypt (chachapoly) %d\n", ret);
        exit(1);
    }
    byte decrypted[16];
    ret = wc_ChaCha20Poly1305_Decrypt(key, iv, NULL, 0, out, sizeof(in), authtag, decrypted);
    if (ret != 0)
    {
        printf("Failed to decrypt (chachapoly) %d\n", ret);
        exit(1);
    }
    // printf("chachapoly successful");
    return ret;
}

int encrypt_des3(Des3 *ctx, const byte *key, int keysize)
{
    const byte iv[] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[] = {0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[100];
    int ret;
    ret = wc_Des3_SetKey(ctx, key, iv, DES_ENCRYPTION);
    if (ret != 0)
    {
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    ret = wc_Des3_CbcEncrypt(ctx, out, in, sizeof(in));
    if (ret != 0)
    {
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    return ret;
}

int main(int argc, char **argv)
{
    const char *key_hex = (const char *)argv[1];
    byte key[500];

    int keysize = chex_decode(key, 500, key_hex, 64);
    // int keysize = hextobin(KEY, key);
    if (keysize < 32)
    {
        printf("Key is too short: %d\n", keysize);
        return -1;
    }

    /* The encryption primitive to use */
    char *mode = argv[2];

    if (!strcmp(mode, "aes-cbc"))
    {
        Aes enc;
        encrypt_aes(&enc, key, keysize, AES_ENCRYPTION, 0);
    }
    else if (!strcmp(mode, "aes-ctr"))
    {
        Aes enc;
        encrypt_aes(&enc, key, keysize, AES_ENCRYPTION, 1);
    }
    else if (!strcmp(mode, "aes-gcm"))
    {
        Aes enc;
        encrypt_aes(&enc, key, keysize, AES_ENCRYPTION, 2);
    }
    else if (!strcmp(mode, "camellia-cbc"))
    {
        Camellia enc;
        encrypt_camellia(&enc, key, keysize);
    }
    else if (!strcmp(mode, "des-cbc"))
    {
        Des3 enc;
        encrypt_des3(&enc, key, keysize);
    }
    else if (!strcmp(mode, "chachapoly1305"))
    {
        chachapoly(key, keysize);
    }
    else if (!strcmp(mode, "hmac-sha1"))
    {
        hmac(key, keysize, 0);
    }
    else if (!strcmp(mode, "hmac-sha256"))
    {
        hmac(key, keysize, 1);
    }
    else if (!strcmp(mode, "hmac-sha512"))
    {
        hmac(key, keysize, 2);
    }
    else if (!strcmp(mode, "ecdh-p256"))
    {
        ecdh(key, keysize, 0);
    }
    else if (!strcmp(mode, "ecdh-p521"))
    {
        ecdh(key, keysize, 1);
    }
    else if (!strcmp(mode, "curve25519"))
    {
        x25519(key, keysize);
        // ecdh(key, keysize, 2);
    }
    else
    {
        printf("Unsupported arguments");
        return 1;
    }

    return 0;
}