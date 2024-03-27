#pragma once
#ifndef HELPERS_H
#define HELPERS_H

void xor_encrypt(const char* data, size_t data_len, const char* key, size_t key_len, char* output);
void print_hex(const char* data, size_t len);

#endif 