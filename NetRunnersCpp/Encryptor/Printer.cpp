#include "Printer.h"
#include "Helpers.h"
#include "Data.h"
#include <stdlib.h>
#include <stdio.h>

int print_header(void)
{
    printf("[+] NOW PRINTING: NETRUNNERS -> GLOBALS.H\n\n");

    // print encrypted buf
    char* ciphertext = (char*)malloc(sizeof(buf) + 1);

    // print buf and key
    xor_encrypt((char*)buf, sizeof(buf), key, key_len, ciphertext);
    printf("extern unsigned char buf[%Iu];\n", sizeof(buf));
    printf("extern char XORKey[%Iu];\n", (key_len + 1));
    free(ciphertext);

    // print encrypted functions
    for (int i = 0; i < num_functions; i++)
    {
        size_t plaintext_len = strlen(function_names[i]);                                       // size of plaintext
        char* ciphertext = (char*)malloc(strlen(function_names[i]) + 1);                        // alloc memory +1 for null terminator
        // print functions
        xor_encrypt(function_names[i], strlen(function_names[i]), key, key_len, ciphertext);    // encrypt
        printf("extern char %s[%Iu];\n",variable_names[i], strlen(function_names[i]));
        free(ciphertext);                                                                       // free memory
    }
    printf("\n");
    return 0;
}

int print_cpp(void)
{
    printf("[+] NOW PRINTING: NETRUNNERS -> GLOBALS.CPP\n\n");

    // print encrypted buf
    char* ciphertext = (char*)malloc(sizeof(buf) + 1);

    xor_encrypt((char*)buf, sizeof(buf), key, key_len, ciphertext);
    printf("static unsigned char buf[%Iu] = ", sizeof(buf));
    print_hex(ciphertext, sizeof(buf));
    printf("char XORKey[%Iu] = \"%s\";\n", (key_len + 1), key);

    // print encrypted functions
    for (int i = 0; i < num_functions; i++)
    {
        size_t plaintext_len = strlen(function_names[i]);                                       
        char* ciphertext = (char*)malloc(strlen(function_names[i]) + 1);                        

        xor_encrypt(function_names[i], strlen(function_names[i]), key, key_len, ciphertext);    
        printf("char %s[%Iu] = ", variable_names[i], strlen(function_names[i]));
        print_hex(ciphertext, plaintext_len);                                                   
        free(ciphertext);                                                                       
    }
    printf("\n");
    return 0;
}