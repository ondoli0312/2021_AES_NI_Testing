#pragma once
#include "type.h"

#define LOAD(X)       _mm_load_si128((__m128i const *)X)
#define LOAD_U(X)     _mm_loadu_si128((__m128i const *)X)
#define STORE(X, Y)   _mm_store_si128((__m128i *)X,Y)
#define ALIGNR(X, Y)  _mm_alignr_epi8(X,Y,4)
#define ADD(X, Y)     _mm_add_epi32(X,Y)
//#define HIGH(X)     _mm_srli_si128(X,8)
#define HIGH(X)       _mm_shuffle_epi32(X, 0x0E)
#define SHA(X, Y, Z)  _mm_sha256rnds2_epu32(X,Y,Z)
#define MSG1(X, Y)    _mm_sha256msg1_epu32(X,Y)
#define MSG2(X, Y)    _mm_sha256msg2_epu32(X,Y)
#define CVLO(X, Y, Z) _mm_shuffle_epi32(_mm_unpacklo_epi64(X,Y),Z)
#define CVHI(X, Y, Z) _mm_shuffle_epi32(_mm_unpackhi_epi64(X,Y),Z)
#define L2B(X)        _mm_shuffle_epi8(X,mask)
#define ALIGN32 __declspec(align(32))

#define ENDIAN_CHANGE(val)	(\
(((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
(((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
(((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
(((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000))

#define ROTL(x,n)				(((x) << (n)) | ((x) >> (32 - (n))))
#define ENDIAN_CHANGE32(val)	((ROTL((val), 8) & 0x00ff00ff) | (ROTL((val), 24) & 0xff00ff00))
int SHANI_256(uint8_t* message, uint64_t msgLen, uint8_t* digest);
void SHANI_256_Test();