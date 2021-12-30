#include "type.h"
#include "AES_NI.h"
#include "SHA256_NI.h"
#include "SHA160_NI.h"
#include "sha.h"
#include <intrin.h>

__int64 cpucycles() {
	return __rdtsc();
}

uint8_t pt[1024 * 1024];
uint8_t out[1024 * 1024];

void SHANI_512_Test()
{
    srand(time(NULL));
    unsigned long long cycle1 = 0;
    unsigned long long cycle2 = 0;
    unsigned long long result = 0;
    for (int i = 0; i < 32; i++)
        out[i] = rand() % 0x100;

    for (int i = 0; i < 100000; i++) {
        for (int i = 0; i < 64; i++) {
            pt[i] = (rand() % 0x100) ^ out[i % 32];
        }
        cycle1 = cpucycles();
        sha512(out, pt, 64); 
        cycle2 = cpucycles();
        result += cycle2 - cycle1;
    }
    printf("SHA256-64byte RDTSC = %10lld\n", ((result) / 100000));
    for (int i = 0; i < 32; i++)
        printf("%02X", out[i]);
    printf("\n");
    getchar();

    for (int i = 0; i < 32; i++)
        out[i] = rand() % 0x100;

    for (int i = 0; i < 100000; i++) {
        for (int i = 0; i < 1024; i++) {
            pt[i] = (rand() % 0x100) ^ out[i % 32];
        }
        cycle1 = cpucycles();
        sha512(out, pt, 1024);
        cycle2 = cpucycles();
        result += cycle2 - cycle1;
    }
    printf("SHA256-1024byte RDTSC = %10lld\n", ((result) / 100000));
    for (int i = 0; i < 32; i++)
        printf("%02X", out[i]);
    printf("\n");
    getchar();

    for (int i = 0; i < 32; i++)
        out[i] = rand() % 0x100;

    for (int i = 0; i < 10000; i++) {
        for (int i = 0; i < 1024 * 1024; i++) {
            pt[i] = (rand() % 0x100) ^ out[i % 32];
        }
        cycle1 = cpucycles();
        sha512(out, pt, 1024 * 1024);
        cycle2 = cpucycles();
        result += cycle2 - cycle1;
    }
    printf("SHA256-1024 * 1024 byte RDTSC = %10lld\n", ((result) / 10000));
    for (int i = 0; i < 32; i++)
        printf("%02X", out[i]);
    printf("\n");
    getchar();
}

int main() {

	AESCBC256_Test();
	//SHANI_256_Test();
	//SHANI_160_Test();

    SHANI_512_Test();
}
