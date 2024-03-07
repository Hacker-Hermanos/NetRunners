#pragma once
#ifndef DECRYPTORS_H
#define DECRYPTORS_H
#include "pch.h"

namespace decryptor
{
	class Decryptor
	{
	public:
		// XOR Decryptor
		static void XORDecrypt(char* data, size_t data_len, char* key, size_t key_len);
	};
}

#endif // !DECRYPTORS_H
