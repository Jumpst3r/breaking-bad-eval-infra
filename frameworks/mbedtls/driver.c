/*
 *  \brief  Generic file encryption program using generic wrappers for configured
 *          security.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* Enable definition of fileno() even when compiling with -std=c99. Must be
 * set before mbedtls_config.h, which pulls in glibc's features.h indirectly.
 * Harmless on other platforms. */
#define _POSIX_C_SOURCE 200112L

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_CIPHER_C) && defined(MBEDTLS_MD_C) && \
 defined(MBEDTLS_FS_IO)
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif


#include <sys/types.h>
#include <unistd.h>


#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  crypt_and_hash <mode> <input filename> <output filename> <cipher> <mbedtls_md> <key>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: crypt_and_hash file file.aes AES-128-CBC SHA1 hex:E76B2413958B00E193\n" \
    "\n"

#if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_CIPHER_C and/or MBEDTLS_MD_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_exit( 0 );
}
#else


int main( int argc, char *argv[] )
{
    int ret = 1, i;
    unsigned n;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    int mode;
    size_t keylen, ilen, olen;
    FILE *fkey, *fin = NULL, *fout = NULL;

    char *p;
    unsigned char IV[16];
    unsigned char key[512];
    unsigned char digest[MBEDTLS_MD_MAX_SIZE];
    unsigned char buffer[1024];
    unsigned char output[1024];
    unsigned char diff;

    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_md_context_t md_ctx;

    off_t filesize, offset;


    mbedtls_cipher_init( &cipher_ctx );
    mbedtls_md_init( &md_ctx );

    /*
     * Parse the command-line arguments.
     */
    if( argc != 7 )
    {
        const int *list;

        mbedtls_printf( USAGE );

        mbedtls_printf( "Available ciphers:\n" );
        list = mbedtls_cipher_list();
        while( *list )
        {
            cipher_info = mbedtls_cipher_info_from_type( *list );
            mbedtls_printf( "  %s\n", mbedtls_cipher_info_get_name( cipher_info ) );
            list++;
        }

        mbedtls_printf( "\nAvailable message digests:\n" );
        list = mbedtls_md_list();
        while( *list )
        {
            md_info = mbedtls_md_info_from_type( *list );
            mbedtls_printf( "  %s\n", mbedtls_md_get_name( md_info ) );
            list++;
        }

        goto exit;
    }

    if( memcmp( argv[6], "hex:", 4 ) == 0 )
    {
        p = &argv[6][4];
        keylen = 0;

        while( sscanf( p, "%02X", (unsigned int*) &n ) > 0 &&
                keylen < (int) sizeof( key ) )
        {
            key[keylen++] = (unsigned char) n;
            p += 2;
        }
    }

    mode = MODE_ENCRYPT;


    if( ( fin = fopen( argv[2], "rb" ) ) == NULL )
    {
        goto exit;
    }

    if( ( fout = fopen( argv[3], "wb+" ) ) == NULL )
    {
        goto exit;
    }

    /*
     * Read the Cipher and MD from the command line
     */

    char *mmode = argv[4];
    char *alg;
    if (!strcmp(mmode, "aes-cbc")) alg = "AES-128-CBC";
    else if (!strcmp(mmode, "aes-ctr")) alg = "AES-128-CTR";
    else if (!strcmp(mmode, "aes-gcm")) alg = "AES-128-GCM";
    else if (!strcmp(mmode, "camellia-cbc")) alg = "CAMELLIA-128-CBC";
    else if (!strcmp(mmode, "aria-cbc")) alg = "ARIA-128-CBC";
    else if (!strcmp(mmode, "des-cbc")) alg = "DES-EDE3-CBC";
    else if (!strcmp(mmode, "hmac-sha256") || !strcmp(mmode, "hmac-sha512")){
        unsigned char hmacResult[32];
        mbedtls_md_context_t ctx;
        char *payload = "some text";
        mbedtls_md_type_t md_type;
        if (!strcmp(mmode, "hmac-sha256")){
            md_type = MBEDTLS_MD_SHA256;
            }
        if  (!strcmp(mmode, "hmac-sha512")){
            md_type = MBEDTLS_MD_SHA512;
            }
        const size_t payloadLength = strlen(payload);
        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1)){
            printf("Failed to md_setup\n");
            exit(1);
        }

        if (mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keylen)){
            printf("Failed hmac start\n");
            exit(1);
        }
        if (mbedtls_md_hmac_update(&ctx, (const unsigned char *) payload, payloadLength)){
            printf("Failed hmac update\n");
            exit(1);
        }
        if (mbedtls_md_hmac_finish(&ctx, hmacResult)){
            printf("Failed hmac finish\n");
            exit(1);
        }
        mbedtls_md_free(&ctx);
   
        exit(0);
    }

    cipher_info = mbedtls_cipher_info_from_string( alg );
    if( cipher_info == NULL )
    {
        goto exit;
    }
    if( ( ret = mbedtls_cipher_setup( &cipher_ctx, cipher_info) ) != 0 )
    {
        goto exit;
    }

    md_info = mbedtls_md_info_from_string( argv[5] );
    if( md_info == NULL )
    {
        goto exit;
    }

    if( mbedtls_md_setup( &md_ctx, md_info, 1 ) != 0 )
    {
        goto exit;
    }

    if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
    {
        perror( "lseek" );
        goto exit;
    }

    if( fseek( fin, 0, SEEK_SET ) < 0 )
    {
        goto exit;
    }

    if( mode == MODE_ENCRYPT )
    {
        /*
         * Generate the initialization vector as:
         * IV = MD( filesize || filename )[0..15]
         */
        for( i = 0; i < 8; i++ )
            buffer[i] = (unsigned char)( filesize >> ( i << 3 ) );

        p = argv[2];

        if( mbedtls_md_starts( &md_ctx ) != 0 )
        {
            goto exit;
        }
        if( mbedtls_md_update( &md_ctx, buffer, 8 ) != 0 )
        {
            goto exit;
        }
        if( mbedtls_md_update( &md_ctx, ( unsigned char * ) p, strlen( p ) )
            != 0 )
        {
            goto exit;
        }
        if( mbedtls_md_finish( &md_ctx, digest ) != 0 )
        {
            goto exit;
        }

        memcpy( IV, digest, 16 );

        /*
         * Append the IV at the beginning of the output.
         */
        if( fwrite( IV, 1, 16, fout ) != 16 )
        {
            goto exit;
        }

        /*
         * Hash the IV and the secret key together 1 times
         * using the result to setup the AES context and HMAC.
         */
        memset( digest, 0,  32 );
        memcpy( digest, IV, 16 );

        for( i = 0; i < 1; i++ )
        {
            if( mbedtls_md_starts( &md_ctx ) != 0 )
            {
                goto exit;
            }
            if( mbedtls_md_update( &md_ctx, digest, 32 ) != 0 )
            {
                goto exit;
            }
            if( mbedtls_md_update( &md_ctx, key, keylen ) != 0 )
            {
                goto exit;
            }
            if( mbedtls_md_finish( &md_ctx, digest ) != 0 )
            {
                goto exit;
            }

        }

        if( mbedtls_cipher_setkey( &cipher_ctx,
                                   digest,
                                   (int) mbedtls_cipher_info_get_key_bitlen( cipher_info ),
                           MBEDTLS_ENCRYPT ) != 0 )
        {
            goto exit;
        }
        if( mbedtls_cipher_set_iv( &cipher_ctx, IV, 16 ) != 0 )
        {
            goto exit;
        }
        if( mbedtls_cipher_reset( &cipher_ctx ) != 0 )
        {
            goto exit;
        }

        if( mbedtls_md_hmac_starts( &md_ctx, digest, 32 ) != 0 )
        {
            goto exit;
        }

        /*
         * Encrypt and write the ciphertext.
         */
        for( offset = 0; offset < filesize; offset += mbedtls_cipher_get_block_size( &cipher_ctx ) )
        {
            ilen = ( (unsigned int) filesize - offset > mbedtls_cipher_get_block_size( &cipher_ctx ) ) ?
                mbedtls_cipher_get_block_size( &cipher_ctx ) : (unsigned int) ( filesize - offset );

            if( fread( buffer, 1, ilen, fin ) != ilen )
            {
                goto exit;
            }

            if( mbedtls_cipher_update( &cipher_ctx, buffer, ilen, output, &olen ) != 0 )
            {
                goto exit;
            }

            if( mbedtls_md_hmac_update( &md_ctx, output, olen ) != 0 )
            {
                goto exit;
            }

            if( fwrite( output, 1, olen, fout ) != olen )
            {
                goto exit;
            }
        }

        if( mbedtls_cipher_finish( &cipher_ctx, output, &olen ) != 0 )
        {
            goto exit;
        }
        if( mbedtls_md_hmac_update( &md_ctx, output, olen ) != 0 )
        {
            goto exit;
        }

        if( fwrite( output, 1, olen, fout ) != olen )
        {
            goto exit;
        }

        /*
         * Finally write the HMAC.
         */
        if( mbedtls_md_hmac_finish( &md_ctx, digest ) != 0 )
        {
            goto exit;
        }

        if( fwrite( digest, 1, mbedtls_md_get_size( md_info ), fout ) != mbedtls_md_get_size( md_info ) )
        {
            goto exit;
        }
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    if( fin )
        fclose( fin );
    if( fout )
        fclose( fout );

    /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[6]. */
    for( i = 0; i < argc; i++ )
        mbedtls_platform_zeroize( argv[i], strlen( argv[i] ) );

    mbedtls_platform_zeroize( IV,     sizeof( IV ) );
    mbedtls_platform_zeroize( key,    sizeof( key ) );
    mbedtls_platform_zeroize( buffer, sizeof( buffer ) );
    mbedtls_platform_zeroize( output, sizeof( output ) );
    mbedtls_platform_zeroize( digest, sizeof( digest ) );

    mbedtls_cipher_free( &cipher_ctx );
    mbedtls_md_free( &md_ctx );

    mbedtls_exit( exit_code );
}
#endif /* MBEDTLS_CIPHER_C && MBEDTLS_MD_C && MBEDTLS_FS_IO */