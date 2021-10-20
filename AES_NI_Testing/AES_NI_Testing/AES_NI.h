#pragma once

//AES_NI.c
void AES_256_Key_Expansion(const unsigned char* userkey, unsigned char* key);
void AES_CBC_encrypt(const unsigned char* in,
	unsigned char* out,
	unsigned char ivec[16],
	unsigned long length,
	unsigned char* key,
	int number_of_rounds);

void AES_CBC_decrypt(const unsigned char* in,
	unsigned char* out,
	unsigned char ivec[16],
	unsigned long length,
	unsigned char* key,
	int number_of_rounds);