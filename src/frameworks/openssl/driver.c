/*
Adapted from
https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/

#include <assert.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <string.h>

void print_it(const char *label, const unsigned char *buff, size_t len)
{
  if (!buff || !len)
    return;

  if (label)
    printf("%s: ", label);

  for (size_t i = 0; i < len; ++i)
    printf("%02X", buff[i]);

  printf("\n");
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext,
            const EVP_CIPHER *algo)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, algo, NULL, key, iv))
    handleErrors();

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, const EVP_CIPHER *algo)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, algo, NULL, key, iv))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag,
                const EVP_CIPHER *algo)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, algo, NULL, NULL, NULL))
    handleErrors();

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    handleErrors();

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    handleErrors();

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Get the tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext,
                const EVP_CIPHER *algo)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the decryption operation. */
  if (!EVP_DecryptInit_ex(ctx, algo, NULL, NULL, NULL))
    handleErrors();

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    handleErrors();

  /* Initialise key and IV */
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    handleErrors();

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    handleErrors();

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0)
  {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  }
  else
  {
    /* Verify failed */
    return -1;
  }
}

EVP_PKEY *read_pkey(const char *filename)
{
  FILE *file = fopen(filename, "rb");
  EVP_PKEY *pkey = NULL;
  PEM_read_PrivateKey(file, &pkey, NULL, NULL);
  fclose(file);
  return pkey;
}

EVP_PKEY *gen_x25519_key()
{
  /* Generate private and public key */
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
  int ret = EVP_PKEY_keygen_init(pctx);
  if (ret <= 0)
  {
    printf("keygen init failed");
  }
  ret = EVP_PKEY_keygen(pctx, &pkey);
  if (ret <= 0)
  {
    printf("keygen failed");
  }
  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

EVP_PKEY *gen_pkey(const int type, const int curve)
{
  /* Create the context for generating the parameters */
  EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
  EVP_PKEY *params = NULL, *key = NULL;

  // skip for x25519 as it does not need params
  if (!(type == EVP_PKEY_EC && curve == NID_X25519))
  {
    if (!(pctx = EVP_PKEY_CTX_new_id(type, NULL)))
      exit(-100);
    if (!EVP_PKEY_paramgen_init(pctx))
      exit(-100);
    /* Set the paramgen parameters according to the type */
    switch (type)
    {
    case EVP_PKEY_EC:
      /* Use the NID_X9_62_prime256v1 named curve - defined in obj_mac.h */
      if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve))
        exit(-100);
      break;
    case EVP_PKEY_DSA:
      /* Set a bit length of 2048 */
      if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 512))
        exit(-100);
      break;

    case EVP_PKEY_DH:
      /* Set a prime length of 2048 */
      if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 512))
        exit(-100);
    }

    /* Generate parameters */
    if (!EVP_PKEY_paramgen(pctx, &params))
      exit(-100);

    if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
      exit(-100);
  }
  else
  {
    if (!(kctx = EVP_PKEY_CTX_new_id(type, NULL)))
      exit(-100);
  }

  if (!EVP_PKEY_keygen_init(kctx))
    exit(-100);

  /* RSA keys set the key length during key generation rather than parameter generation! */
  if (type == EVP_PKEY_RSA)
  {
    if (!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 512))
      exit(-100);
  }

  /* Generate the key */
  if (EVP_PKEY_keygen(kctx, &key) <= 0)
    exit(-100);

  if (pctx != NULL)
    EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX_free(kctx);

  return key;
}

int ecdh(unsigned char *key, int key_len, const int type, const int curve, const char *fname)
{
  EVP_PKEY_CTX *ctx;
  size_t keylen;
  EVP_PKEY *pkey, *peerkey;
  // somehow curve25519 keygen needs a custom function
  // not sure what causes this
  if (curve == NID_X25519)
  {
    pkey = read_pkey(fname);
    peerkey = gen_x25519_key();
  }
  else
  {
    pkey = read_pkey(fname);
    peerkey = gen_pkey(type, curve);
  }

  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx)
  {
    printf("pkey ctx failed");
    exit(-10);
  }
  /* Error occurred */
  if (EVP_PKEY_derive_init(ctx) <= 0)
  {
    printf("pkey derive failed");
    exit(-10);
  }
  if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0)
  {
    printf("pkey derive peer failed");
    exit(-10);
  }
  /* Determine buffer length */
  if (EVP_PKEY_derive(ctx, NULL, &keylen) <= 0)
  {
    printf("pkey derive 2 failed");
    exit(-10);
  }

  if (keylen > key_len)
  {
    printf("keylen difference");
    exit(-10);
  }
  // skey = OPENSSL_malloc(skeylen);

  if (EVP_PKEY_derive(ctx, key, &keylen) <= 0)
  {
    printf("pkey derive 3 failed");
    exit(-10);
  }

  for (int i = 0; i < keylen; i++)
  {
    printf("%02x", key[i]);
  }

  /* Shared secret is skey bytes written to buffer skey */
  EVP_PKEY_CTX_free(ctx);
  return 0;
}

size_t sign(const char *msg, const int curve, const char *fname)
{
  EVP_PKEY *key;
  if (curve == NID_X25519)
  {
    // key = gen_x25519_key();
    key = read_pkey(fname);
  }
  else
  {
    // key = gen_pkey(EVP_PKEY_EC, curve);
    key = read_pkey(fname);
  }

  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;
  size_t slen = 0;

  unsigned char *sig = NULL;

  /* Create the Message Digest Context */
  if (!(mdctx = EVP_MD_CTX_create()))
    exit(-200);

  /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
  if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key))
    exit(-200);

  /* Call update with the message */
  if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg)))
    exit(-200);

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
   * signature. Length is returned in slen */
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen))
    exit(-200);
  /* Allocate memory for the signature based on size in slen */
  if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen))))
    exit(-200);
  /* Obtain the signature */
  if (1 != EVP_DigestSignFinal(mdctx, sig, &slen))
    exit(-200);

  /* Clean up */
  if (sig && !ret)
    OPENSSL_free(sig);
  if (mdctx)
    EVP_MD_CTX_destroy(mdctx);

  for (int i = 0; i < slen; i++)
  {
    printf("%02x", sig[i]);
  }

  return slen;
}

int main(int argc, char **argv)
{
  /*
   * Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)argv[1];

  /* The encryption primitive to use */
  char *mode = argv[2];

  const EVP_CIPHER *alg = NULL;
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"012345678901234567890123456789012345";

  /* Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox";
  size_t p_len = strlen((char *)plaintext);

  if (!strcmp(mode, "compare"))
  {
    int LEN = 16;
    uint8_t b1[LEN];
    uint8_t b2[LEN];
    // 128 bit fixed
    char *fixed = "000102030405060708090A0B0C0D0E0F";

    hextobin(b2, fixed);
    hextobin(b1, argv[1]);
    int r = CRYPTO_memcmp(b1, b2, LEN);
    return r;
  }

  else if (!strcmp(mode, "aes-cbc"))
    alg = EVP_aes_128_cbc();
  else if (!strcmp(mode, "aes-ctr"))
    alg = EVP_aes_128_ctr();
  else if (!strcmp(mode, "aes-gcm"))
    alg = EVP_aes_128_gcm();
  else if (!strcmp(mode, "camellia-cbc"))
    alg = EVP_camellia_128_cbc();
  // else if (!strcmp(mode, "aria-cbc"))
  //   alg = EVP_aria_192_cbc();
  else if (!strcmp(mode, "des-cbc"))
    alg = EVP_des_ede_cbc();
  // else if (!strcmp(mode, "sm4-cbc"))
  //   alg = EVP_sm4_cbc();
  else if (!strcmp(mode, "chacha_poly1305"))
    alg = EVP_chacha20_poly1305();
  // // the following only work with legacy 1.1.x OpensSSL versions
  // else if (!strcmp(mode, "bf-cbc"))
  //   alg = EVP_bf_cbc();
  // else if (!strcmp(mode, "cast-cbc"))
  //   alg = EVP_cast5_cbc();
  else if (!strcmp(mode, "hmac-sha1") || !strcmp(mode, "hmac-sha256") || !strcmp(mode, "hmac-sha512") || !strcmp(mode, "hmac-blake2"))
  {
    unsigned char md[256];
    unsigned char bkey[256];
    int klen = hextobin(bkey, (const char *)key);
    uint8_t *res;
    unsigned int md_len;
    if (!strcmp(mode, "hmac-sha1"))
      res = HMAC(EVP_sha1(), bkey, klen, plaintext, p_len, md, &md_len);
    else if (!strcmp(mode, "hmac-sha256"))
      res = HMAC(EVP_sha256(), bkey, klen, plaintext, p_len, md, &md_len);
    else if (!strcmp(mode, "hmac-sha512"))
      res = HMAC(EVP_sha512(), bkey, klen, plaintext, p_len, md, &md_len);
    else if (!strcmp(mode, "hmac-blake2"))
      res = HMAC(EVP_blake2s256(), bkey, klen, plaintext, p_len, md, &md_len);
    else
      res = NULL;
    if (res == NULL)
      exit(-123);
    printf("success");
    return 0;
  }
  else if (!strcmp(mode, "ecdh-p256"))
  {
    int dkeylen = 256;
    unsigned char dkey[dkeylen];

    // reseed random generator with input key
    // RAND_seed(key, strlen((const char *)key));

    ecdh(dkey, dkeylen, EVP_PKEY_EC, NID_X9_62_prime256v1, argv[1]);
    printf("successful");
    return 0;
  }
  else if (!strcmp(mode, "x25519"))
  {
    int dkeylen = 256;
    unsigned char dkey[dkeylen];

    // reseed random generator with input key
    // RAND_seed(key, strlen((const char *)key));

    ecdh(dkey, dkeylen, EVP_PKEY_EC, NID_X25519, argv[1]);
    printf("successful");
    return 0;
  }
  else if (!strcmp(mode, "ecdsa"))
  {
    // reseed random generator with input key
    // RAND_seed(key, strlen((const char *)key));

    size_t len = sign((const char *)plaintext, NID_X9_62_prime256v1, argv[1]);
    printf("successful: %d\n", (int)len);
    return 0;
  }
  else
  {
    return -1;
  }

  /*
   * Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, depending on the
   * algorithm and mode.
   */
  unsigned char ciphertext[128];
  unsigned char tag[128];

  int ciphertext_len;

  /* Encrypt the plaintext */
  if (!strcmp(mode, "aes-gcm"))
    ciphertext_len =
        gcm_encrypt(plaintext, strlen((char *)plaintext), NULL, 0, key, iv, strlen(iv), ciphertext, tag, alg);
  else
    ciphertext_len =
        encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, alg);

  if (ciphertext_len <= 0)
  {
    printf("encrypt unsuccessful\n");
    exit(-1);
  }

  unsigned char decrypted[128];
  int decrypted_len;
  if (!strcmp(mode, "aes-gcm"))
    decrypted_len = gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag, key, iv, strlen(iv), decrypted, alg);
  else
    decrypted_len = decrypt(ciphertext, ciphertext_len, key, iv, decrypted, alg);

  if (strlen((const char *)plaintext) != decrypted_len || memcmp(plaintext, decrypted, decrypted_len) != 0)
  {
    printf("huh?");
  }
  else
  {
    printf("success");
  }

  return 0;
}
