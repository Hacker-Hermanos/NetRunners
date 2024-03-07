#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "Helpers.h"

void xor_encrypt(const char* data, size_t data_len, const char* key, size_t key_len, char* output)
{
    for (size_t i = 0; i < data_len; ++i)
    {
        output[i] = data[i] ^ key[i % key_len];
    }
}

void print_hex(const char* data, size_t len)
{
    printf("{ ");
    for (size_t i = 0; i < len; ++i)
    {
        printf("0x%02x", (unsigned char)data[i]);
        if (i < len - 1) printf(", ");
    }
    printf(" };\n");
}