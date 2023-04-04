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
#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <fipsmodule/rand/internal.h>
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

EVP_PKEY *read_key(const char *filename)
{
  int max_size = 512;
  uint8_t buffer[max_size];
  int size = 0;
  memset(buffer, 0, max_size);
  FILE *fptr = fopen(filename, "rb");
  if (fptr == NULL)
  {
    printf("could not open key file: %s\n", filename);
    exit(-1);
  }

  size = fread(buffer, sizeof(uint8_t), max_size, fptr);

  printf("read %d bytes from %s\n", size, filename);

  fclose(fptr);

  CBS cbs;
  CBS_init(&cbs, buffer, size);

  printf("data:\n");
  for (int i = 0; i < size; i++)
    printf("%02x", buffer[i]);
  printf("\n");

  EVP_PKEY *key = EVP_parse_private_key(&cbs);
  if (key == NULL)
  {
    printf("could not parse key\n");
    exit(-9);
  }
  return key;
}

void read_two_keys(const char *filename, EVP_PKEY **key1, EVP_PKEY **key2)
{
  int max_size = 1024;
  uint8_t buffer[max_size];
  int size = 0;
  memset(buffer, 0, max_size);
  FILE *fptr = fopen(filename, "rb");
  if (fptr == NULL)
  {
    printf("could not open key file: %s\n", filename);
    exit(-1);
  }

  size = fread(buffer, sizeof(uint8_t), max_size, fptr);

  printf("read %d bytes from %s\n", size, filename);

  fclose(fptr);

  CBS cbs;
  CBS_init(&cbs, buffer, size);

  printf("data:\n");
  for (int i = 0; i < size; i++)
    printf("%02x", buffer[i]);
  printf("\n");

  *key1 = EVP_parse_private_key(&cbs);
  if (*key1 == NULL)
  {
    printf("could not parse key\n");
    exit(-9);
  }
  *key2 = EVP_parse_private_key(&cbs);
  if (*key2 == NULL)
  {
    printf("could not parse key\n");
    exit(-9);
  }

  if (EVP_PKEY_cmp(*key1, *key2) == 1)
  {
    printf("the two keys are the same\n");
    exit(-5);
  }

  return;
}

int ecdh(const int type, const int curve, const char *key1_fname)
{
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey, *peerkey;
  // somehow curve25519 keygen needs a custom function
  // not sure what causes this
  // if (curve == NID_X25519)
  // {
  //   pkey = gen_x25519_key();
  //   peerkey = gen_x25519_key();
  // }
  // else
  // {
  //   pkey = gen_pkey(type, curve);
  //   peerkey = gen_pkey(type, curve);
  // }

  read_two_keys(key1_fname, &pkey, &peerkey);

  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL)
    exit(-10);
  /* Error occurred */
  if (EVP_PKEY_derive_init(ctx) != 1)
    /* Error */
    exit(-11);
  if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
    /* Error */
    exit(-12);

  size_t keylen;
  /* Determine buffer length */
  if (EVP_PKEY_derive(ctx, NULL, &keylen) <= 0)
    /* Error */
    exit(-13);

  printf("keylen: %d\n", keylen);
  // if (keylen > key_len)
  //   exit(-20);
  // skey = OPENSSL_malloc(skeylen);
  // uint8_t key[keylen];
  uint8_t *key = OPENSSL_malloc(keylen);

  if (EVP_PKEY_derive(ctx, key, &keylen) <= 0)
    /* Error */
    exit(-15);

  printf("key: ");
  for (int i = 0; i < keylen; i++)
  {
    printf("%02x", key[i]);
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(peerkey);
  OPENSSL_free(key);
  return 0;
}

size_t sign(const char *msg, const int curve, const char *key_filename)
{
  EVP_PKEY *key = read_key(key_filename);

  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;
  size_t slen = 0;

  unsigned char *sig = NULL;

  /* Create the Message Digest Context */
  if (!(mdctx = EVP_MD_CTX_create()))
  {
    printf("could not create md ctx");
    exit(-1);
  }

  /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
  if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key))
  {
    printf("could not digest init");
    exit(-1);
  }

  /* Call update with the message */
  if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg)))
  {
    printf("could not EVP_DigestSignUpdate");
    exit(-1);
  }

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
   * signature. Length is returned in slen */
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen))
  {
    printf("could not EVP_DigestSignFinal");
    exit(-1);
  }
  /* Allocate memory for the signature based on size in slen */
  if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen))))
  {
    printf("could not OPENSSL_malloc");
    exit(-1);
  }
  /* Obtain the signature */
  if (1 != EVP_DigestSignFinal(mdctx, sig, &slen))
  {
    printf("could not EVP_DigestSignFinal");
    exit(-1);
  }

  printf("signature: ");
  for (int i = 0; i < slen; i++)
  {
    printf("%02x", sig[i]);
  }

  /* Clean up */
  if (sig && !ret)
    OPENSSL_free(sig);
  if (mdctx)
    EVP_MD_CTX_destroy(mdctx);

  EVP_PKEY_free(key);

  return slen;
}

int main(int argc, char **argv)
{
  CRYPTO_library_init();
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
  // size_t iv_len = strlen((char *)iv);

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
  else if (!strcmp(mode, "des-cbc"))
    alg = EVP_des_ede_cbc();
  else if (!strcmp(mode, "aes-gcm") || !strcmp(mode, "chacha_poly1305"))
  {
    unsigned char ciphertext[256];
    size_t clen;
    unsigned char *aad = (unsigned char *)"lorem ipsum";
    size_t aad_len = strlen((char *)aad);

    unsigned char bkey[256];
    int klen = hextobin(bkey, (const char *)key);
    if (klen < 32)
    {
      printf("unsupported key length: %d\n", klen);
      exit(-456);
    }
    const EVP_AEAD *aead;
    if (!strcmp(mode, "aes-gcm"))
      aead = EVP_aead_aes_128_gcm();
    else if (!strcmp(mode, "chacha_poly1305"))
      aead = EVP_aead_chacha20_poly1305();
    else
      exit(-456);

    int res;
    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new(aead, bkey, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH);

    if (ctx == NULL)
    {
      printf("could not create aead ctx\n");
      exit(-456);
    }

    /* Encrypt the plaintext */
    res = EVP_AEAD_CTX_seal(ctx, ciphertext, &clen, sizeof(ciphertext), iv,
                            EVP_AEAD_nonce_length(aead), plaintext, p_len, aad, aad_len);
    if (res != 1)
    {
      printf("could not perform aead seal\n");
      exit(-456);
    }

    unsigned char decrypted[128];
    size_t dec_len;

    res = EVP_AEAD_CTX_open(ctx, decrypted, &dec_len, sizeof(decrypted), iv,
                            EVP_AEAD_nonce_length(aead), ciphertext, clen, aad, aad_len);
    if (res != 1)
    {
      printf("could not perform aead open\n");
      exit(-456);
    }

    if (strlen((const char *)plaintext) != dec_len || memcmp(plaintext, decrypted, dec_len) != 0)
    {
      printf("huh?");
    }
    else
    {
      printf("success");
    }
    EVP_AEAD_CTX_cleanup(ctx);
    return 0;
  }
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
      res = HMAC(EVP_blake2b256(), bkey, klen, plaintext, p_len, md, &md_len);
    else
      res = NULL;
    if (res == NULL)
      exit(-123);
    printf("success");
    return 0;
  }
  else if (!strcmp(mode, "ecdh-p256"))
  {
    // reseed random generator with input key
    // this is pretty hacky as it misuses with additional data
    // this call also adds the additional data to the entropy
    // this can be verified by using deterministic and removing the lines below
    // RAND_seed(key, strlen((const char *)key));
    // uint8_t temp[8];
    // RAND_bytes_with_additional_data(temp, 1, key);

    ecdh(EVP_PKEY_EC, NID_X9_62_prime256v1, argv[1]);
    printf("successful");
    return 0;
  }
  else if (!strcmp(mode, "x25519"))
  {
    // reseed random generator with input key
    // RAND_seed(key, strlen((const char *)key));
    // uint8_t temp[8];
    // RAND_bytes_with_additional_data(temp, 1, key);

    ecdh(EVP_PKEY_EC, NID_X25519, argv[1]);
    printf("successful");
    return 0;
  }
  else if (!strcmp(mode, "ecdsa"))
  {
    // reseed random generator with input key
    // RAND_seed(key, strlen((const char *)key));
    // uint8_t temp[8];
    // RAND_bytes_with_additional_data(temp, 1, key);

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

  int ciphertext_len;

  /* Encrypt the plaintext */
  ciphertext_len =
      encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, alg);

  unsigned char decrypted[128];
  int decrypted_len = decrypt(ciphertext, ciphertext_len, key, iv, decrypted, alg);

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
