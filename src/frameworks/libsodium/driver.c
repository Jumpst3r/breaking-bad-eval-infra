#include <sodium.h>
#include <stdio.h>

int main(void)
{
    if (sodium_init() < 0) {
        printf("panic! the library couldn't be initialized; it is not safe to use");
        exit(-1);
    }
    return 0;
}