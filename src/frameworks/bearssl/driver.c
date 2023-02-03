
#include <assert.h>
#include <bearssl.h>
#include <string.h>

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
  unsigned char *key = (unsigned char *)argv[1];

  /* The encryption primitive to use */
  char *mode = argv[2];

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";

  /* Authenticated data */
  unsigned char *ad = (unsigned char *)"Lorem Ipsum";

  /* Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox";

  if (!strcmp(mode, "aes-cbc"))
  {
    br_aes_ct_cbcenc_keys ctx;
    br_aes_ct_cbcenc_init(&ctx, key, 16);

    br_aes_ct_cbcenc_run(&ctx, iv, plaintext, sizeof(plaintext)); // inplace updates plaintext

    br_aes_ct_cbcdec_keys ctx2;
    br_aes_ct_cbcdec_init(&ctx2, key, 16);
    br_aes_ct_cbcdec_run(&ctx2, iv, plaintext, 32); // len fixed to 32 bytes
  }
  else if (!strcmp(mode, "aes-ctr"))
  {
    br_aes_ct_ctr_keys ctx;
    br_aes_ct_ctr_init(&ctx, key, 16);

    br_aes_ct_ctr_run(&ctx, iv, 0, plaintext, sizeof(plaintext)); // inplace updates plaintext
  }
  else if (!strcmp(mode, "aes-gcm"))
  {
    br_gcm_context ctx;
    br_aes_ct_ctr_keys bctx;
    br_aes_ct_ctr_init(&bctx, key, 16);
    br_gcm_init(&ctx, &bctx.vtable, br_ghash_ctmul);
    br_gcm_reset(&ctx, iv, sizeof(iv));

    br_gcm_aad_inject(&ctx, ad, sizeof(ad));
    br_gcm_flip(&ctx);
    br_gcm_run(&ctx, 1 /*encrypt*/, plaintext, sizeof(plaintext));

    unsigned char tag[16];
    br_gcm_get_tag(&ctx, tag);
  }
  else if (!strcmp(mode, "chacha-poly1305"))
  {
    unsigned char tag[32];
    br_poly1305_ctmul_run(key, iv, plaintext, sizeof(plaintext),
                          ad, sizeof(ad), tag, br_chacha20_ct_run, 1);

    br_poly1305_ctmul_run(key, iv, plaintext, sizeof(plaintext),
                          ad, sizeof(ad), tag, br_chacha20_ct_run, 0);
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

    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, plaintext, sizeof(plaintext));
    br_hmac_outCT(&hc, plaintext, sizeof(plaintext), 16, sizeof(plaintext), output);
  }
  else if (!strcmp(mode, "rsa"))
  {
  }

  // // the following only work with legacy 1.1.x OpensSSL versions
  // else if (!strcmp(mode, "bf-cbc"))
  //   alg = EVP_bf_cbc();
  // else if (!strcmp(mode, "cast-cbc"))
  //   alg = EVP_cast5_cbc();
  // else if (!strcmp(mode, "hmac-sha256") || !strcmp(mode, "hmac-sha512")) {
  //   unsigned char *sig = NULL;
  //   unsigned char bkey[256];
  //   int res = hextobin(bkey, key);
  //   EVP_PKEY *skey = NULL;
  //   if (!strcmp(mode, "hmac-sha256"))
  //     hn = "SHA256";
  //   else if (!strcmp(mode, "hmac-sha512"))
  //     hn = "SHA512";
  //   make_keys(&skey, bkey, res);
  //   size_t slen = 0;
  //   hmac_it(plaintext, strlen((char *)plaintext), &sig, &slen, skey);
  //   return 0;
  // } else {
  //   return 1;
  // }

  // /*
  //  * Buffer for ciphertext. Ensure the buffer is long enough for the
  //  * ciphertext which may be longer than the plaintext, depending on the
  //  * algorithm and mode.
  //  */
  // unsigned char ciphertext[128];

  // /* Buffer for the decrypted text */
  // unsigned char decryptedtext[128];

  // int decryptedtext_len, ciphertext_len;

  // /* Encrypt the plaintext */
  // ciphertext_len =
  //     encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, alg);

  // /* Do something useful with the ciphertext here */
  // // printf("Ciphertext is:\n");
  // // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  return 0;
}
