#include <stdio.h>
#include <string.h>

extern int crypt_and_hash(int argc, char *argv[]);
extern int ecdh(char *ec, char *rand, size_t r_len);
extern int ecdsa(char *ec, char *rand, size_t r_len);

int main(int argc, char *argv[])
{
    // If first arg is either 0 or 1, then go to crypt and hash
    if (argc > 2 && (!strcmp(argv[1], "0") || !strcmp(argv[1], "1")))
    {
        return crypt_and_hash(argc, argv);
    }
    if (argc > 2 && strstr(argv[1], "ecdh") != NULL)
    {
        return ecdh(argv[1], argv[2], strlen(argv[2]));
    }
    if (argc > 2 && strstr(argv[1], "ecdsa") != NULL)
    {
        return ecdsa(argv[1], argv[2], strlen(argv[2]));
    }

    printf("Incorrect arguments\n");
    return -1;
}