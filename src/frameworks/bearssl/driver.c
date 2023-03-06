
#include <assert.h>
#include <bearssl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int hextobin(unsigned char *dst, const char *src)
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

int main(int argc, char **argv)
{
  /*
   * Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A key */
  /* A 256 bit key in hex */
  char *key_hex = (char *)argv[1];
  uint32_t key_len = 32;
  uint8_t key[32];
  int len = hextobin(key, key_hex);
  if (len < 32)
  {
    printf("insufficient key length\n");
    return -1;
  }

  /* The encryption primitive to use */
  char *mode = argv[2];

  /* A 128 bit IV */
  unsigned char *iv_c = (unsigned char *)"0123456789012345";
  unsigned char iv[16];
  memcpy(iv, iv_c, 16);

  /* Authenticated data */
  unsigned char *ad = (unsigned char *)"Lorem Ipsum";

  /* Message to be encrypted */
  unsigned char *plaintext_c = (unsigned char *)"The quick brown fox jumps over the lazy dog";
  unsigned char plaintext[32];
  memcpy(plaintext, plaintext_c, 32);

  if (!strcmp(mode, "aes-cbc"))
  {
    br_aes_ct_cbcenc_keys ctx;
    br_aes_ct_cbcenc_init(&ctx, key, 32);

    br_aes_ct_cbcenc_run(&ctx, iv, plaintext, br_aes_ct_BLOCK_SIZE); // inplace updates plaintext

    br_aes_ct_cbcdec_keys ctx2;
    br_aes_ct_cbcdec_init(&ctx2, key, 32);
    br_aes_ct_cbcdec_run(&ctx2, iv, plaintext, 32); // len fixed to 32 bytes
    printf("AES-CBC successful");
  }
  else if (!strcmp(mode, "aes-ctr"))
  {
    br_aes_ct_ctr_keys ctx;
    br_aes_ct_ctr_init(&ctx, key, 32);

    br_aes_ct_ctr_run(&ctx, iv, 0, plaintext, sizeof(plaintext)); // inplace updates plaintext
    printf("AES-CTR successful");
  }
  else if (!strcmp(mode, "aes-gcm"))
  {
    br_gcm_context ctx;
    br_aes_ct_ctr_keys bctx;
    br_aes_ct_ctr_init(&bctx, key, 32);
    br_gcm_init(&ctx, &bctx.vtable, br_ghash_ctmul);
    br_gcm_reset(&ctx, iv, sizeof(iv));

    br_gcm_aad_inject(&ctx, ad, sizeof(ad));
    br_gcm_flip(&ctx);
    br_gcm_run(&ctx, 1 /*encrypt*/, plaintext, sizeof(plaintext));

    unsigned char tag[16];
    br_gcm_get_tag(&ctx, tag);
    printf("AES-GCM successful");
  }
  else if (!strcmp(mode, "chacha-poly1305"))
  {
    unsigned char tag[32];
    br_poly1305_ctmul_run(key, iv, plaintext, sizeof(plaintext),
                          ad, sizeof(ad), tag, br_chacha20_ct_run, 1);

    br_poly1305_ctmul_run(key, iv, plaintext, sizeof(plaintext),
                          ad, sizeof(ad), tag, br_chacha20_ct_run, 0);
    printf("chachapoly successful");
  }
  else if (strstr(mode, "hmac") != NULL)
  {
    unsigned char output[128];
    br_hmac_context hc;
    br_hmac_key_context kc;

    if (strstr(mode, "sha1") != NULL)
      br_hmac_key_init(&kc, &br_sha1_vtable, key, sizeof(key));
    else if (strstr(mode, "sha2") != NULL)
      br_hmac_key_init(&kc, &br_sha256_vtable, key, sizeof(key));
    else
    {
      printf("Unsupported hash algorithm\n");
      return -1;
    }

    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, plaintext, sizeof(plaintext));
    br_hmac_outCT(&hc, plaintext, sizeof(plaintext), 16, sizeof(plaintext), output);
    printf("hmac successful");
  }
  else if (strstr(mode, "ecdsa") != NULL)
  {
    // br_ec_impl *ec;
    br_hash_compat_context hc;
    const br_hash_class *hf = &br_sha256_vtable;

    // lets first hash the data to be signed
    uint8_t hash_value[br_sha256_SIZE];
    hf->init(&hc.vtable);
    hf->update(&hc.vtable, plaintext, sizeof(plaintext));
    hf->out(&hc.vtable, hash_value);

    const br_ec_impl *ec = br_ec_get_default();
    //  = strstr(mode, "25519") != NULL ? &br_ec_c25519_i31 : &br_ec_prime_i31;

    int curve_id = 0;
    if (strstr(mode, "p256") != NULL)
      curve_id = BR_EC_secp256r1;
    else if (strstr(mode, "521") != NULL)
      curve_id = BR_EC_secp521r1;
    else if (strstr(mode, "384") != NULL)
      curve_id = BR_EC_secp384r1;
    else
    {
      printf("Curve not supported\n");
      return -1;
    }

    // setup rng
    br_hmac_drbg_context rng;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, key, 32);

    // Generate new EC keypair
    br_ec_private_key ec_key;
    unsigned char kbuf[BR_EC_KBUF_PRIV_MAX_SIZE];
    int res = br_ec_keygen(&rng.vtable, ec, &ec_key, kbuf, curve_id);
    if (res == 0)
    {
      printf("ECDSA gen privkey not successful\n");
      exit(-1);
    }

    // compute pubkey
    br_ec_public_key pubkey;
    unsigned char pubkbuf[BR_EC_KBUF_PUB_MAX_SIZE];
    res = br_ec_compute_pub(ec, &pubkey, pubkbuf, &ec_key);
    if (res == 0)
    {
      printf("ECDSA gen pubkey not successful\n");
      exit(-1);
    }

    // ECDSA signing
    uint8_t sig[256];
    br_ecdsa_sign sign = &br_ecdsa_i31_sign_raw;
    size_t len = sign(ec, hf, hash_value, &ec_key, sig);

    if (len == 0)
    {
      printf("ECDSA sign not successful\n");
      exit(-1);
    }

    br_ecdsa_vrfy verify = &br_ecdsa_i31_vrfy_raw;
    res = verify(ec, hash_value, br_sha256_SIZE, &pubkey, sig, len);
    if (res == 0)
    {
      printf("ECDSA verify not successful\n");
      exit(-1);
    }
    printf("ECDSA successful");
  }
  else if (strstr(mode, "ecdh") != NULL || strstr(mode, "25519") != NULL)
  {
    // // br_ec_impl *ec;
    // br_hash_compat_context hc;
    // const br_hash_class *hf = &br_sha256_vtable;

    // // lets first hash the data to be signed
    // uint8_t hash_value[br_sha256_SIZE];
    // hf->init(&hc.vtable);
    // hf->update(&hc.vtable, plaintext, sizeof(plaintext));
    // hf->out(&hc.vtable, hash_value);

    const br_ec_impl *ec = br_ec_get_default();
    //  = strstr(mode, "25519") != NULL ? &br_ec_c25519_i31 : &br_ec_prime_i31;

    int curve_id = 0;
    if (strstr(mode, "p256") != NULL)
      curve_id = BR_EC_secp256r1;
    else if (strstr(mode, "521") != NULL)
      curve_id = BR_EC_secp521r1;
    else if (strstr(mode, "384") != NULL)
      curve_id = BR_EC_secp384r1;
    else if (strstr(mode, "25519") != NULL)
      curve_id = BR_EC_curve25519;
    else
    {
      printf("Curve not supported\n");
      return -1;
    }

    // setup rng
    br_hmac_drbg_context rng;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, key, 32);

    // Generate new EC keypair
    br_ec_private_key ec_key1, ec_key2;
    unsigned char kbuf1[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char kbuf2[BR_EC_KBUF_PRIV_MAX_SIZE];
    size_t ec_key1_len = br_ec_keygen(&rng.vtable, ec, &ec_key1, kbuf1, curve_id);
    if (ec_key1_len == 0)
    {
      printf("ECDH gen privkey not successful\n");
      exit(-1);
    }
    size_t ec_key2_len = br_ec_keygen(&rng.vtable, ec, &ec_key2, kbuf2, curve_id);
    if (ec_key1_len == 0)
    {
      printf("ECDH gen privkey not successful\n");
      exit(-1);
    }

    // compute pubkey
    br_ec_public_key pubkey1, pubkey2;
    unsigned char pubkbuf1[BR_EC_KBUF_PUB_MAX_SIZE];
    unsigned char pubkbuf2[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t pubkey1_len = br_ec_compute_pub(ec, &pubkey1, pubkbuf1, &ec_key1);
    if (pubkey1_len == 0)
    {
      printf("ECDH gen pubkey not successful\n");
      exit(-1);
    }
    size_t pubkey2_len = br_ec_compute_pub(ec, &pubkey2, pubkbuf2, &ec_key2);
    if (pubkey2_len == 0)
    {
      printf("ECDH gen pubkey not successful\n");
      exit(-1);
    }

    // ECDH key agreement
    int res1 = ec->mul(pubkbuf1, pubkey1_len, kbuf2, ec_key2_len, curve_id);
    int res2 = ec->mul(pubkbuf2, pubkey2_len, kbuf1, ec_key1_len, curve_id);
    if (res1 != 1 || res2 != 1)
    {
      printf("ec multiplication failed\n");
      return -1;
    }

    if (memcmp(pubkbuf1, pubkbuf2, pubkey1_len) != 0)
    {
      printf("ECDH key agreement failed\n");
      return -1;
    }

    printf("ECDH successful");
  }
  else if (!strcmp(mode, "rsa"))
  {
    // br_rsa_public pub = br_rsa_public_get_default();
    // br_rsa_private priv = br_rsa_private_get_default();
    br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
    br_rsa_pkcs1_vrfy vrfy = br_rsa_pkcs1_vrfy_get_default();
    // br_rsa_pss_sign pss_sign = br_rsa_pss_sign_get_default();
    // br_rsa_pss_vrfy pss_vrfy = br_rsa_pss_vrfy_get_default();
    br_rsa_oaep_encrypt menc = br_rsa_oaep_encrypt_get_default();
    br_rsa_oaep_decrypt mdec = br_rsa_oaep_decrypt_get_default();
    br_rsa_keygen kgen = br_rsa_keygen_get_default();

    // setup rng
    br_hmac_drbg_context rng;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, key, 32);

    br_rsa_private_key sk;
    br_rsa_public_key pk;

    size_t rsa_size = 1024;
    unsigned char kbuf_priv[BR_RSA_KBUF_PRIV_SIZE(rsa_size)];
    unsigned char kbuf_pub[BR_RSA_KBUF_PUB_SIZE(rsa_size)];

    // generate keypair
    if (!kgen(&rng.vtable, &sk, kbuf_priv, &pk, kbuf_pub, rsa_size, 3))
    {
      printf("RSA keygen failed");
      exit(-1);
    }

    // lets first hash the data to be signed
    br_hash_compat_context hc;
    const br_hash_class *hf = &br_sha256_vtable;

    uint8_t hash_value[br_sha256_SIZE];
    hf->init(&hc.vtable);
    hf->update(&hc.vtable, plaintext, sizeof(plaintext));
    hf->out(&hc.vtable, hash_value);

    // PKCS1.5 (rsa sign)
    unsigned char sig[128];
    if (!sign(BR_HASH_OID_SHA256, hash_value, br_sha256_SIZE, &sk, sig))
    {
      printf("RSA sign failed");
      exit(-1);
    }
    unsigned char hash_out[br_sha256_SIZE];
    if (vrfy(sig, sizeof(sig), BR_HASH_OID_SHA1, br_sha256_SIZE, &pk, hash_out) != 1)
    {
      printf("RSA verify failed");
      exit(-1);
    }

    // OAEP
    unsigned char m[1024];
    size_t len = menc(&rng.vtable, &br_sha256_vtable, NULL, 0, &pk, m, sizeof(m), plaintext, sizeof(plaintext));
    if (len == 0)
    {
      printf("RSA OAEP enc failed");
      exit(-1);
    }

    if (!mdec(&br_sha256_vtable, NULL, 0, &sk, m, &len))
    {
      printf("RSA OAEP dec failed");
      exit(-1);
    }

    printf("RSA successful");
  }
  else
  {
    printf("Unsupported algorithm\n");
    return -1;
  }

  return 0;
}
