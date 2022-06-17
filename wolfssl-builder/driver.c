/*
Adapted from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
(WolfSSL OpenSSL EVP compat mode)

*/

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>

#include <string.h>

void handleErrors(void)
{
    abort();
}



// from BearSSL test_crypto.c - hextobin()
static size_t
hextobin(unsigned char *dst, const char *src)
{
	size_t num;
	unsigned acc;
	int z;

	num = 0;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int c = *src ++;
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
			*dst ++ = (acc << 4) + c;
			num ++;
		} else {
			acc = c;
		}
		z = !z;
	}
	return num;
}


int encrypt_aes(Aes *ctx, const byte *key,int keysize, int dir){
    const byte iv[] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[32] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[32];
    int ret;
    ret = wc_AesSetKey(ctx,key, keysize, iv, dir);
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    ret = wc_AesCbcEncrypt(ctx, out, in, sizeof(in));
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    return ret;
}

int encrypt_camellia(Camellia *ctx, const byte *key,int keysize){
    const byte iv[] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[32] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[32];
    int ret;
    ret = wc_CamelliaSetKey(ctx,key, keysize, iv);
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    ret = wc_CamelliaCbcEncrypt(ctx, out, in, sizeof(in));
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    return ret;
}


int encrypt_des3(Des3 *ctx, const byte *key,int keysize){
    const byte iv[] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[100];
    int ret;
    ret = wc_Des3_SetKey(ctx, key, iv, DES_ENCRYPTION);
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    ret = wc_Des3_CbcEncrypt(ctx, out, in, sizeof(in));
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    return ret;
}


int main (int argc, char **argv)
{
    const char *key = (const char*) argv[1];
    byte *KEY = calloc(500, sizeof(byte)) ;

    int keysize = hextobin(KEY, key);

    /* The encryption primitive to use */
    char *mode =  argv[2];

    if (!strcmp(mode, "aes-cbc")) {
        Aes enc;
        encrypt_aes(&enc, KEY, keysize, AES_ENCRYPTION);
    }
    else if (!strcmp(mode, "camellia-cbc")) {
        Camellia enc;
        encrypt_camellia(&enc, KEY, keysize);
    }
    else if (!strcmp(mode, "des-cbc")) {
        Des3 enc;
        encrypt_des3(&enc, KEY, keysize);
    }

    return 0;
}