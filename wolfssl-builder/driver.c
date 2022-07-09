/*
Adapted from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
(WolfSSL OpenSSL EVP compat mode)

*/

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>


#include <string.h>

void handleErrors(void)
{
    abort();
}



// from BearSSL test_crypto.c - hextobin(). Force no-inline to properly remove key parsing secret dep leaks from report by matching the symbold name
static size_t
 __attribute__ ((noinline)) hextobin(unsigned char *dst, const char *src)
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

/*
mode 0: SHA256
mode 1: SHA512
*/
int hmac(const byte *key,int keysize, int mode){
    int ret;
    Hmac hmac;
    const byte in[32] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    const byte hash[256];
    if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0) {
        printf("Issue initializing hmac\n");
        exit(1);
    }

    ret = wc_HmacSetKey(&hmac, (mode == 0) ? WC_SHA256 : WC_SHA512, key, keysize);
    if (ret != 0){
        printf("Issue with set key\n");
                exit(1);
}

    ret = wc_HmacUpdate(&hmac, in, 32);
    if (ret != 0){
        printf("Issue with update\n");
                exit(1);

}
    ret = wc_HmacFinal(&hmac, hash);
    if (ret != 0){
        printf("Issue with hmac final\n");
        exit(1);
    }
    return ret;
}


/*
mode 0: cbc
mode 1: ctr
mode 2: gcm
*/
int encrypt_aes(Aes *ctx, const byte *key,int keysize, int dir, int mode){
    const byte iv[] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte in[32] = { 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD, 0xA, 0xB, 0xC, 0xD};
    byte out[32];
    int ret;
    ret = wc_AesSetKey(ctx,key, keysize, iv, dir);
    if (ret != 0){
        printf("Failed to set key: ERRNO %d\n", ret);
        exit(1);
    }
    if (mode == 0){
        ret = wc_AesCbcEncrypt(ctx, out, in, sizeof(in));
    }
    else if (mode == 1){
        ret = wc_AesCtrEncrypt(ctx, out, in, sizeof(in));
    }
    else if (mode == 2){
        ret = wc_AesGcmSetKey(ctx, key, sizeof(key));
        if (ret != 0) return 1;
        byte auth_tag[32]; 
        byte auth_vec[32]; 
        ret = wc_AesGcmEncrypt(ctx, out, in,  sizeof(in), iv, sizeof(iv), auth_tag, sizeof(auth_tag), auth_vec, sizeof(auth_vec));
        if (ret != 0) return 1;
    }
   
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
        encrypt_aes(&enc, KEY, keysize, AES_ENCRYPTION, 0);
    }
    else if (!strcmp(mode, "aes-ctr")) {
        Aes enc;
        encrypt_aes(&enc, KEY, keysize, AES_ENCRYPTION, 1);
    }
    else if (!strcmp(mode, "aes-gcm")) {
        Aes enc;
        encrypt_aes(&enc, KEY, keysize, AES_ENCRYPTION, 2);
    }
    else if (!strcmp(mode, "camellia-cbc")) {
        Camellia enc;
        encrypt_camellia(&enc, KEY, keysize);
    }
    else if (!strcmp(mode, "des-cbc")) {
        Des3 enc;
        encrypt_des3(&enc, KEY, keysize);
    }
    else if (!strcmp(mode, "hmac-sha256")){
        hmac(KEY, keysize, 0);
    }
    else if (!strcmp(mode, "hmac-sha512")){
        hmac(KEY, keysize, 1);
    }
    else{
        return 1;
    }

    return 0;
}