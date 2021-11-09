#pragma once
#include "type.h"
#define ALIGN32 __declspec(align(32))
#define ENDIAN_CHANGE(val)	(\
(((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
(((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
(((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
(((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000))

#define ROTL(x,n)				(((x) << (n)) | ((x) >> (32 - (n))))
#define ENDIAN_CHANGE32(val)	((ROTL((val), 8) & 0x00ff00ff) | (ROTL((val), 24) & 0xff00ff00))

void SHA160_NI(uint8_t* message, uint64_t msgLen, uint8_t* digest);
void SHANI_160_Test();