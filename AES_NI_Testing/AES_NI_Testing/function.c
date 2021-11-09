#include "type.h"
#include "AES_NI.h"
#include "SHA256_NI.h"
#include "SHA160_NI.h"
#include <intrin.h>

__int64 cpucycles() {
	return __rdtsc();
}

int main() {
	//AESCBC256_Test();
	//SHANI_256_Test();
	SHANI_160_Test();
	
}