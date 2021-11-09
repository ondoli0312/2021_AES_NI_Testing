#include "type.h"
#include "SHA256_NI.h"
const ALIGN32 uint32_t constant[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static void SHANI_Block(uint32_t* state, const uint8_t* msg, uint32_t num_blocks){
    const __m128i mask = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
    int i, j;
    __m128i A0, C0, ABEF, CDGH, X0, Y0, Ki, W0[4];

    X0 = LOAD(state + 0);
    Y0 = LOAD(state + 1);

    A0 = CVLO(X0, Y0, 0x1B);
    C0 = CVHI(X0, Y0, 0x1B);

    while (num_blocks > 0) {
        ABEF = A0;
        CDGH = C0;
        for (i = 0; i < 4; i++) {
            Ki = LOAD(constant + i);
            W0[i] = L2B(LOAD_U(msg + i));
            X0 = ADD(W0[i], Ki);
            Y0 = HIGH(X0);
            C0 = SHA(C0, A0, X0);
            A0 = SHA(A0, C0, Y0);
        }
        for (j = 1; j < 4; j++) {
            for (i = 0; i < 4; i++) {
                Ki = LOAD(constant + 4 * j + i);
                X0 = MSG1(W0[i], W0[(i + 1) % 4]);
                Y0 = ALIGNR(W0[(i + 3) % 4], W0[(i + 2) % 4]);
                X0 = ADD(X0, Y0);
                W0[i] = MSG2(X0, W0[(i + 3) % 4]);
                X0 = ADD(W0[i], Ki);
                Y0 = HIGH(X0);
                C0 = SHA(C0, A0, X0);
                A0 = SHA(A0, C0, Y0);
            }
        }
        A0 = ADD(A0, ABEF);
        C0 = ADD(C0, CDGH);
        msg += 64;
        num_blocks--;
    }

    X0 = CVHI(A0, C0, 0xB1);
    Y0 = CVLO(A0, C0, 0xB1);

    STORE(state + 0, X0);
    STORE(state + 1, Y0);
}

int SHANI_256(uint8_t* message, uint64_t msgLen, uint8_t* digest) {
    uint32_t i = 0;
    uint32_t num_blocks = msgLen / 64;
    uint32_t rem_bytes = msgLen % 64;
    ALIGN32 uint8_t pad[128];
    ALIGN32 uint32_t state[8];

    state[0] = 0x6a09e667; 
    state[1] = 0xbb67ae85; 
    state[2] = 0x3c6ef372; 
    state[3] = 0xa54ff53a; 
    state[4] = 0x510e527f; 
    state[5] = 0x9b05688c; 
    state[6] = 0x1f83d9ab; 
    state[7] = 0x5be0cd19; 
    
    SHANI_Block(state, message, num_blocks);

    //Padding
    for (i = 0; i < rem_bytes; i++) {
        pad[i] = message[64 * num_blocks + i];
    }
    pad[rem_bytes] = 0x80;

    if (rem_bytes < 56) {
        for (i = rem_bytes + 1; i < 56; i++) {
            pad[i] = 0x0;
        }
        ((uint64_t*)pad)[7] = ENDIAN_CHANGE(msgLen << 3);
        SHANI_Block(state, pad, 1);
    }
    else {
        for (i = rem_bytes + 1; i < 120; i++) {
            pad[i] = 0;
        }
        ((uint64_t*)pad)[15] = ENDIAN_CHANGE(msgLen << 3);
        SHANI_Block(state, pad, 2);
    }
    for (i = 0; i < 8; i++) {
        ((uint32_t*)digest)[i] = ENDIAN_CHANGE32(state[i]);
    }
    return 1;
}

uint8_t pt[1024 * 1024];
uint8_t out[32];
void SHANI_256_Test()
{
    srand(time(NULL));
    unsigned long long cycle1 = 0;
    unsigned long long cycle2 = 0;
    unsigned long long result = 0;
    for (int i = 0; i < 32; i++)
        out[i] = rand() % 0x100;

    for (int i = 0; i < 100000; i++) {
        for (int i = 0; i < 64; i++) {
            pt[i] = (rand() % 0x100) ^ out[i%32];
        }
        cycle1 = cpucycles();
        SHANI_256(pt, 64, out);
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
        SHANI_256(pt, 1024, out);
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
        SHANI_256(pt, 1024 * 1024, out);
        cycle2 = cpucycles();
        result += cycle2 - cycle1;
    }
    printf("SHA256-1024 * 1024 byte RDTSC = %10lld\n", ((result) / 10000));
    for (int i = 0; i < 32; i++)
        printf("%02X", out[i]);
    printf("\n");
    getchar();
}