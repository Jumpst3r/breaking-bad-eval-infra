#include <stddef.h>
/* from OpenSSL crypto/cpuid.c
 * DOC: CRYPTO_memcmp - Constant time memory comparison
 * https://www.openssl.org/docs/man3.0/man3/CRYPTO_memcmp.html
 *
 * 
 * The volatile is used to to ensure that the compiler generates code that reads
 * all values from the array and doesn't try to optimize this away. The standard
 * doesn't actually require this behavior if the original data pointed to is
 * not volatile, but compilers do this in practice anyway.
 *
 * There are also assembler versions of this function.
 */
int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}