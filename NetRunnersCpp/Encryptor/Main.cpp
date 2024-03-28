#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Printer.h"

int main(void)
{
    //char plaintext[] = "VirtualProtect";
    //char* ciphertext = (char*)malloc(strlen(plaintext) + 1); 
    //xor_encrypt(plaintext, plaintext_len, key, key_len, ciphertext);
    //print_hex(ciphertext, plaintext_len);

    // print all function_names for obfuscation
    print_header();
    print_cpp();
    return 0;
}
