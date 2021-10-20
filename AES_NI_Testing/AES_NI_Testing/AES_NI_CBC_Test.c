#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#include "AES_NI.h"
#define AES256
#define LENGTH 64
#if !defined (ALIGN16)
#	if defined(__GNUC__)
#		define ALIGN16	__attribute__((aligned(16)))
#else
#	define ALIGN16	__declspec(align(16))
#endif
#endif

typedef struct KEY_SCHEDULE {
	ALIGN16 unsigned char KEY[16 * 15];
	unsigned int nr;
} AES_KEY;

ALIGN16 uint8_t AES256_TEST_KEY[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

ALIGN16 uint8_t AES_TEST_VECTOR[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

ALIGN16 uint8_t CBC_IV[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

ALIGN16 uint8_t CBC256_EXPECTED[] = {
	0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
	0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
	0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
	0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
	0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
	0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
	0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
	0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

void print_m128i_with_string(char* string, __m128i data) {
	unsigned char* pointer = (unsigned char*)&data;
	printf("%-40s[0x", string);
	for (int i = 0; i < 16; i++) {
		printf("%02X ", pointer[i]);
	}
	printf("]\n");
}

void print_m128i_with_string_short(char* string, __m128i data, int length) {
	unsigned char* pointer = (unsigned char*)&data;
	printf("%-40s[0x", string);
	for (int i = 0; i < length; i++) {
		printf("%02X ", pointer[i]);
	}
	printf("]\n");
}

int AES_set_encrypt_key(const unsigned char* userKey, const int bits,
	AES_KEY* key)
{
	if (!userKey || !key)
		return -1;
	if (bits == 256)
	{
		AES_256_Key_Expansion(userKey, key->KEY);
		key->nr = 14;
		return 0;
	}
	return -2;
}
int AES_set_decrypt_key(const unsigned char* userKey, const int bits,
	AES_KEY* key)
{
	int i, nr;
	;
	AES_KEY temp_key;
	__m128i* Key_Schedule = (__m128i*) key->KEY;
	__m128i* Temp_Key_Schedule = (__m128i*) temp_key.KEY;
	if (!userKey || !key)
		return -1;
	if (AES_set_encrypt_key(userKey, bits, &temp_key) == -2)
		return -2;
	nr = temp_key.nr;
	key->nr = nr;
	Key_Schedule[nr] = Temp_Key_Schedule[0];
	Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
	Key_Schedule[nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
	Key_Schedule[nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
	Key_Schedule[nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
	Key_Schedule[nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
	Key_Schedule[nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
	Key_Schedule[nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
	Key_Schedule[nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
	Key_Schedule[nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
	if (nr > 10)
	{
		Key_Schedule[nr - 10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
		Key_Schedule[nr - 11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
	}
	if (nr > 12)
	{
		Key_Schedule[nr - 12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
		Key_Schedule[nr - 13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
	}
	Key_Schedule[0] = Temp_Key_Schedule[nr];
	return 0;
}

int AES_CBC_256_Test()
{
	AES_KEY key;
	AES_KEY decrypt_key;
	uint8_t* PLAINTEXT;
	uint8_t* CIPHERTEXT;
	uint8_t* DECRYPTEDTEXT;
	uint8_t* EXPECTED_CIPHERTEXT;
	uint8_t* CIPHER_KEY;

	int i, j, key_length;
	/*if (!Check_CPU_support_AES()) {
		printf("CPU does not support AES instruction set. Bailing out.\n");
		return 1;
	}*/
	printf("CPU support AES instruction set. \n\n");

#ifdef AES256
#define STR "Performing AES256-CBC. \n"
	CIPHER_KEY = AES256_TEST_KEY;
	EXPECTED_CIPHERTEXT = CBC256_EXPECTED;
	key_length = 256;
#endif
	PLAINTEXT = (uint8_t*)malloc(LENGTH);
	if (PLAINTEXT == NULL)
		return -1;
	CIPHERTEXT = (uint8_t*)malloc(LENGTH);
	if (CIPHERTEXT == NULL)
		return -1;
	DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH);
	if (DECRYPTEDTEXT == NULL)
		return -1;

	for (i = 0; i < LENGTH/16/4; i++) {
		for (j = 0; j < 4; j++) {
			_mm_storeu_si128(&((__m128i*)PLAINTEXT)[i * 4 + j], ((__m128i*)AES_TEST_VECTOR)[j]);
		}
		for (j = i * 4; j < LENGTH / 16; j++) {
			_mm_storeu_si128(&((__m128i*)PLAINTEXT)[j], ((__m128i*)AES_TEST_VECTOR)[j % 4]);
		}
		if (LENGTH % 16) {
			_mm_storeu_si128(&((__m128i*)PLAINTEXT)[j], ((__m128i*)AES_TEST_VECTOR)[j % 4]);
		}
	}

	AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
	AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);

	AES_CBC_encrypt(PLAINTEXT, CIPHERTEXT, CBC_IV, LENGTH, key.KEY, key.nr);
	AES_CBC_decrypt(CIPHERTEXT, DECRYPTEDTEXT, CBC_IV, LENGTH, decrypt_key.KEY, decrypt_key.nr);

	printf("%s\n", STR);
	printf("The Cihper Key : \n");
	print_m128i_with_string("", ((__m128i*)CIPHER_KEY)[0]);
	if (key_length > 128)
		print_m128i_with_string_short("", ((__m128i*)CIPHER_KEY)[1], (key_length / 8) - 16);
	
	printf("The Key Schedule : \n");
	for (i = 0; i < key.nr; i++) 
		print_m128i_with_string("", ((__m128i*)key.KEY)[i]);

	printf("The PLAINTEXT : \n");
	for (i = 0; i < LENGTH / 16; i++)
		print_m128i_with_string("", ((__m128i*)PLAINTEXT)[i]);
	if (LENGTH % 16)
		print_m128i_with_string_short("", ((__m128i*)PLAINTEXT)[i], LENGTH % 16);

	printf("\nThe CIPHERTEXT : \n");
	for (i = 0; i < LENGTH / 16; i++)
		print_m128i_with_string("", ((__m128i*)CIPHERTEXT)[i]);
	if (LENGTH % 16)
		print_m128i_with_string_short("", ((__m128i*)CIPHERTEXT)[i], LENGTH % 16);

	for (i = 0; i < ((64 < LENGTH) ? 64 : LENGTH); i++) {
		if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i % 64]) {
			printf("The ciphertext is not equal to the expected ciphertext. \n\n");
			return 1;
		}
	}
	printf("\nThe CIPHERTEXT equals to the EXPECTED CIPHERTEXT for bytes where expected text was entered.\n\n");
	for (i = 0; i < LENGTH; i++) {
		if (DECRYPTEDTEXT[i] != PLAINTEXT[i % (16 * 4)]) {
			printf("%x", DECRYPTEDTEXT[i]);
			printf("The DECRYPTED TEXT is not equal to the original""PLAINTEXT. \n\n");
			return 1;
		}
	}
	printf("The DECRYPTED TEXT equals to the original PLAINTEXT. \n\n");
}

int main()
{
	AES_CBC_256_Test();
}