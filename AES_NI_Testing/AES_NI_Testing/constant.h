#include "sha512_defs.h"

#define K512_0  UINT64_C(0x428a2f98d728ae22)
#define K512_1  UINT64_C(0x7137449123ef65cd)
#define K512_2  UINT64_C(0xb5c0fbcfec4d3b2f)
#define K512_3  UINT64_C(0xe9b5dba58189dbbc)
#define K512_4  UINT64_C(0x3956c25bf348b538)
#define K512_5  UINT64_C(0x59f111f1b605d019)
#define K512_6  UINT64_C(0x923f82a4af194f9b)
#define K512_7  UINT64_C(0xab1c5ed5da6d8118)
#define K512_8  UINT64_C(0xd807aa98a3030242)
#define K512_9  UINT64_C(0x12835b0145706fbe)
#define K512_10 UINT64_C(0x243185be4ee4b28c)
#define K512_11 UINT64_C(0x550c7dc3d5ffb4e2)
#define K512_12 UINT64_C(0x72be5d74f27b896f)
#define K512_13 UINT64_C(0x80deb1fe3b1696b1)
#define K512_14 UINT64_C(0x9bdc06a725c71235)
#define K512_15 UINT64_C(0xc19bf174cf692694)
#define K512_16 UINT64_C(0xe49b69c19ef14ad2)
#define K512_17 UINT64_C(0xefbe4786384f25e3)
#define K512_18 UINT64_C(0x0fc19dc68b8cd5b5)
#define K512_19 UINT64_C(0x240ca1cc77ac9c65)
#define K512_20 UINT64_C(0x2de92c6f592b0275)
#define K512_21 UINT64_C(0x4a7484aa6ea6e483)
#define K512_22 UINT64_C(0x5cb0a9dcbd41fbd4)
#define K512_23 UINT64_C(0x76f988da831153b5)
#define K512_24 UINT64_C(0x983e5152ee66dfab)
#define K512_25 UINT64_C(0xa831c66d2db43210)
#define K512_26 UINT64_C(0xb00327c898fb213f)
#define K512_27 UINT64_C(0xbf597fc7beef0ee4)
#define K512_28 UINT64_C(0xc6e00bf33da88fc2)
#define K512_29 UINT64_C(0xd5a79147930aa725)
#define K512_30 UINT64_C(0x06ca6351e003826f)
#define K512_31 UINT64_C(0x142929670a0e6e70)
#define K512_32 UINT64_C(0x27b70a8546d22ffc)
#define K512_33 UINT64_C(0x2e1b21385c26c926)
#define K512_34 UINT64_C(0x4d2c6dfc5ac42aed)
#define K512_35 UINT64_C(0x53380d139d95b3df)
#define K512_36 UINT64_C(0x650a73548baf63de)
#define K512_37 UINT64_C(0x766a0abb3c77b2a8)
#define K512_38 UINT64_C(0x81c2c92e47edaee6)
#define K512_39 UINT64_C(0x92722c851482353b)
#define K512_40 UINT64_C(0xa2bfe8a14cf10364)
#define K512_41 UINT64_C(0xa81a664bbc423001)
#define K512_42 UINT64_C(0xc24b8b70d0f89791)
#define K512_43 UINT64_C(0xc76c51a30654be30)
#define K512_44 UINT64_C(0xd192e819d6ef5218)
#define K512_45 UINT64_C(0xd69906245565a910)
#define K512_46 UINT64_C(0xf40e35855771202a)
#define K512_47 UINT64_C(0x106aa07032bbd1b8)
#define K512_48 UINT64_C(0x19a4c116b8d2d0c8)
#define K512_49 UINT64_C(0x1e376c085141ab53)
#define K512_50 UINT64_C(0x2748774cdf8eeb99)
#define K512_51 UINT64_C(0x34b0bcb5e19b48a8)
#define K512_52 UINT64_C(0x391c0cb3c5c95a63)
#define K512_53 UINT64_C(0x4ed8aa4ae3418acb)
#define K512_54 UINT64_C(0x5b9cca4f7763e373)
#define K512_55 UINT64_C(0x682e6ff3d6b2b8a3)
#define K512_56 UINT64_C(0x748f82ee5defb2fc)
#define K512_57 UINT64_C(0x78a5636f43172f60)
#define K512_58 UINT64_C(0x84c87814a1f0ab72)
#define K512_59 UINT64_C(0x8cc702081a6439ec)
#define K512_60 UINT64_C(0x90befffa23631e28)
#define K512_61 UINT64_C(0xa4506cebde82bde9)
#define K512_62 UINT64_C(0xbef9a3f7b2c67915)
#define K512_63 UINT64_C(0xc67178f2e372532b)
#define K512_64 UINT64_C(0xca273eceea26619c)
#define K512_65 UINT64_C(0xd186b8c721c0c207)
#define K512_66 UINT64_C(0xeada7dd6cde0eb1e)
#define K512_67 UINT64_C(0xf57d4f7fee6ed178)
#define K512_68 UINT64_C(0x06f067aa72176fba)
#define K512_69 UINT64_C(0x0a637dc5a2c898a6)
#define K512_70 UINT64_C(0x113f9804bef90dae)
#define K512_71 UINT64_C(0x1b710b35131c471b)
#define K512_72 UINT64_C(0x28db77f523047d84)
#define K512_73 UINT64_C(0x32caab7b40c72493)
#define K512_74 UINT64_C(0x3c9ebe0a15c9bebc)
#define K512_75 UINT64_C(0x431d67c49c100d4c)
#define K512_76 UINT64_C(0x4cc5d4becb3e42b6)
#define K512_77 UINT64_C(0x597f299cfc657e2a)
#define K512_78 UINT64_C(0x5fcb6fab3ad6faec)
#define K512_79 UINT64_C(0x6c44198c4a475817)