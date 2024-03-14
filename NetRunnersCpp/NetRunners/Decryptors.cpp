
#include "Decryptors.h"

// XOR Decryptor
void decryptor::Decryptor::XORDecrypt(char* data, size_t data_len, char* key, size_t key_len)
{
	int j = 0;

	for (int i = 0; i < data_len; i++)
	{
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}
