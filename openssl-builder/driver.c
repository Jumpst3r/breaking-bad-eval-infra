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
#include <string.h>

char *hn;

void print_it(const char *label, const unsigned char *buff, size_t len) {
  if (!buff || !len)
    return;

  if (label)
    printf("%s: ", label);

  for (size_t i = 0; i < len; ++i)
    printf("%02X", buff[i]);

  printf("\n");
}

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

int hextobin(unsigned char *dst, const char *src) {
  size_t num;
  unsigned acc;
  int z;

  num = 0;
  z = 0;
  acc = 0;
  while (*src != 0) {
    int c = *src++;
    if (c >= '0' && c <= '9') {
      c -= '0';
    } else if (c >= 'A' && c <= 'F') {
      c -= ('A' - 10);
    } else if (c >= 'a' && c <= 'f') {
      c -= ('a' - 10);
    } else {
      continue;
    }
    if (z) {
      *dst++ = (acc << 4) + c;
      num++;
    } else {
      acc = c;
    }
    z = !z;
  }
  return num;
}

// https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
int hmac_it(const unsigned char *msg, size_t mlen, unsigned char **val,
            size_t *vlen, EVP_PKEY *pkey) {
  /* Returned to caller */
  int result = 0;
  EVP_MD_CTX *ctx = NULL;
  size_t req = 0;
  int rc;

  if (!msg || !mlen || !val || !pkey)
    return 0;

  *val = NULL;
  *vlen = 0;

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
  if (rc != 1) {
    printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignUpdate(ctx, msg, mlen);
  if (rc != 1) {
    printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignFinal(ctx, NULL, &req);
  if (rc != 1) {
    printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
    goto err;
  }

  *val = OPENSSL_malloc(req);
  if (*val == NULL) {
    printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  *vlen = req;
  rc = EVP_DigestSignFinal(ctx, *val, vlen);
  if (rc != 1) {
    printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc,
           ERR_get_error());
    goto err;
  }

  result = 1;

err:
  EVP_MD_CTX_free(ctx);
  if (!result) {
    OPENSSL_free(*val);
    *val = NULL;
  }
  return result;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext,
            const EVP_CIPHER *algo) {
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

int make_keys(EVP_PKEY **skey, unsigned char *hkey, int keylen) {

  int result = -1;

  do {
    const EVP_MD *md = EVP_get_digestbyname(hn);
    assert(md != NULL);
    if (md == NULL) {
      printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    int size = EVP_MD_size(md);
    assert(size >= 16);
    if (!(size >= 16)) {
      printf("EVP_MD_size failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    if (!(size <= keylen)) {
      printf("EVP_MD_size is too large, sizeof key: %d, sizeof md: %d \n",
             keylen, size);
      return 1;
    }

    *skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, size);
    assert(*skey != NULL);
    if (*skey == NULL) {
      printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
      break;
    }

    result = 0;

  } while (0);

  OPENSSL_cleanse(hkey, sizeof(hkey));

  /* Convert to 0/1 result */
  return !!result;
}

int main(int argc, char **argv) {
  /*
   * Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)argv[1];

  /* The encryption primitive to use */
  char *mode = argv[2];

  const EVP_CIPHER *alg;
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";

  /* Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox";

  if (!strcmp(mode, "compare")) {
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
    alg = EVP_aes_128_ctr();
  else if (!strcmp(mode, "camellia-cbc"))
    alg = EVP_camellia_128_cbc();
  else if (!strcmp(mode, "aria-cbc"))
    alg = EVP_aria_192_cbc();
  else if (!strcmp(mode, "des-cbc"))
    alg = EVP_des_ede_cbc();
  else if (!strcmp(mode, "sm4-cbc"))
    alg = EVP_sm4_cbc();
  else if (!strcmp(mode, "chacha_poly1305"))
    alg = EVP_chacha20_poly1305();
  // the following only work with legacy 1.1.x OpensSSL versions
  else if (!strcmp(mode, "bf-cbc"))
    alg = EVP_bf_cbc();
  else if (!strcmp(mode, "cast-cbc"))
    alg = EVP_cast5_cbc();
  else if (!strcmp(mode, "hmac-sha256") || !strcmp(mode, "hmac-sha512")) {
    unsigned char *sig = NULL;
    unsigned char bkey[256];
    int res = hextobin(bkey, key);
    EVP_PKEY *skey = NULL;
    if (!strcmp(mode, "hmac-sha256"))
      hn = "SHA256";
    else if (!strcmp(mode, "hmac-sha512"))
      hn = "SHA512";
    make_keys(&skey, bkey, res);
    size_t slen = 0;
    hmac_it(plaintext, strlen((char *)plaintext), &sig, &slen, skey);
    return 0;
  } else {
    return 1;
  }

  /*
   * Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, depending on the
   * algorithm and mode.
   */
  unsigned char ciphertext[128];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Encrypt the plaintext */
  ciphertext_len =
      encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, alg);

  /* Do something useful with the ciphertext here */
  // printf("Ciphertext is:\n");
  // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  return 0;
}
