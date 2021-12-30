#include <immintrin.h>
#include "defs.h"
#include "sha512_defs.h"
#include "constant.h"
#define _INLINE_ static inline
typedef __m128i vec_t;
#define SHA512_WORD_BIT_LEN (8 * sizeof(sha512_word_t))
#define ADD32(a, b)             (_mm_add_epi32(a, b))
#define ADD64(a, b)             (_mm_add_epi64(a, b))
#define ALIGNR8(a, b, mask)     (_mm_alignr_epi8(a, b, mask))
#define BLEND16(a, b, mask)     (_mm_blend_epi16(a, b, mask))
#define LOAD(mem)               (_mm_loadu_si128((const __m128i *)(mem)))
#define MADD32(src, imm8, a, b) (_mm_mask_add_epi32(src, imm8, a, b))
#define ROR32(a, imm8)          (_mm_ror_epi32(a, imm8))
#define ROR64(a, imm8)          (_mm_ror_epi64(a, imm8))
#define SETR32(e0, e1, e2, e3)  (_mm_setr_epi32(e0, e1, e2, e3))
#define SET64(e1, e0)           (_mm_set_epi64x(e1, e0))
#define SHUF8(a, mask)          (_mm_shuffle_epi8(a, mask))
#define SHUF32(a, mask)         (_mm_shuffle_epi32(a, mask))
#define SLL32(a, imm8)          (_mm_slli_epi32(a, imm8))
#define SLL64(a, imm8)          (_mm_slli_epi64(a, imm8))
#define SRL32(a, imm8)          (_mm_srli_epi32(a, imm8))
#define SRL64(a, imm8)          (_mm_srli_epi64(a, imm8))
#define STORE(mem, reg)         (_mm_store_si128((__m128i *)(mem), reg))
#define XOR(A,B)                ((_mm_xor_si128(A,B)))

#define LOW32X2_MASK  (0x3)
#define HIGH32X2_MASK (0xc)

#define MS_VEC_NUM   (SHA512_BLOCK_BYTE_LEN / sizeof(vec_t))
#define WORDS_IN_VEC (16 / sizeof(sha512_word_t))

_INLINE_ void rotate_x(vec_t x[8])
{
    const vec_t tmp = x[0];

    for (size_t i = 0; i < 7; i++) {
        x[i] = x[i + 1];
    }

    x[7] = tmp;
}

ALIGN(64) const sha512_word_t sha512_x1[SHA512_ROUNDS_NUM] = {
  K512_0,  K512_1,  K512_2,  K512_3,  K512_4,  K512_5,  K512_6,  K512_7,  K512_8,
  K512_9,  K512_10, K512_11, K512_12, K512_13, K512_14, K512_15, K512_16, K512_17,
  K512_18, K512_19, K512_20, K512_21, K512_22, K512_23, K512_24, K512_25, K512_26,
  K512_27, K512_28, K512_29, K512_30, K512_31, K512_32, K512_33, K512_34, K512_35,
  K512_36, K512_37, K512_38, K512_39, K512_40, K512_41, K512_42, K512_43, K512_44,
  K512_45, K512_46, K512_47, K512_48, K512_49, K512_50, K512_51, K512_52, K512_53,
  K512_54, K512_55, K512_56, K512_57, K512_58, K512_59, K512_60, K512_61, K512_62,
  K512_63, K512_64, K512_65, K512_66, K512_67, K512_68, K512_69, K512_70, K512_71,
  K512_72, K512_73, K512_74, K512_75, K512_76, K512_77, K512_78, K512_79,
};


//
//
//_INLINE_ vec_t sha512_update_x_avx(vec_t x[8], const sha512_word_t* sha512_x1_p)
//{
//    vec_t t[4];
//
//    // This function recieves 8 128-bit registers X[7:0]=q[15:0] and calculates:
//    // s0 = sigma0(q[(i + 1) % 16])
//    // s1 = sigma1(q[(i + 14) % 16])
//    // q[i % 16] += s0 + s1 + q[(i + 9) % 16]
//    //
//    // For X[0]=q[3:0]
//    //
//    // This means that
//    // res[0] depends on q[1] (for s0) q[14] (for s1) and q[9]
//    // res[1] depends on q[2] (for s0) q[15] (for s1) and q[10]
//    // res[2] depends on q[3] (for s0) res[0] (for s1) and q[11]
//    // res[3] depends on q[4] (for s0) res[1] (for s1) and q[12]
//
//    t[0] = ALIGNR8(x[1], x[0], 8);                      // q[2:1]
//    t[3] = ALIGNR8(x[5], x[4], 8);                      // q[10:9]
//    t[2] = SRL64(t[0], sigma0_0);                       // q[2:1] >> s0[0]
//    x[0] = ADD64(x[0], t[3]);                           // q[1:0] + q[10:9]
//    t[3] = SRL64(t[0], sigma0_2);                       // q[2:1] >> s0[2]
//    t[1] = SLL64(t[0], SHA512_WORD_BIT_LEN - sigma0_1); // q[2:1] << (64 - s0[1])
//    t[0] = XOR(t[3], t[2]);                             // (q[2:1] >> s0[2]) ^
//                                                        //   (q[2:1] >> s0[0])
//    t[2] = SRL64(t[2], sigma0_1 - sigma0_0);            // q[2:1] >> s0[1]
//    t[0] = XOR(t[0], t[1]);                                       // (q[2:1] >> s0[2]) ^
//                                                        //  (q[2:1] >> s0[0]) ^
//                                                        //  q[2:1] << (64 - s0[1])
//    t[1] = SLL64(t[1], sigma0_1 - sigma0_0);            // q[2:1] << (64 - s0[0])
//    t[0] = XOR(t[2], t[1]);                                  // sigma1(q[2:1])
//    t[3] = SRL64(x[7], sigma1_2);                       // q[15:14] >> s1[2]
//    t[2] = SLL64(x[7], SHA512_WORD_BIT_LEN - sigma1_1); // q[15:14] >> (64 - s1[1])
//    x[0] = ADD64(x[0], t[0]);                           // q[1:0] + sigma0(q[2:1])
//    t[1] = SRL64(x[7], sigma1_0);                       // q[15:14] >> s1[0]
//    t[3] = XOR(t[3], t[2]);                                        // q[15:14] >> s1[2] ^
//                                                        //  q[15:14] >> (64 - s1[1])
//    t[2] = SLL64(t[2], sigma1_1 - sigma1_0);            // q[15:14] >> (64 - s1[0])
//    t[3] = XOR(t[3], t[1]);                                        // q[15:14] >> s1[2] ^
//                  //  q[15:14] >> (64 - s1[1] ^
//                  //  q[15:14] >> s1[0]
//    t[1] = SRL64(t[1], sigma1_1 - sigma1_0); // q[15:14] >> s1[1]
//    t[3] = XOR(t[2], t[1]);                       // sigma1(q[15:14])
//
//    // q[1:0] + q[10:9] + sigma1(q[15:14]) + sigma0(q[2:1])
//    x[0] = ADD64(x[0], t[3]);
//
//    rotate_x(x);
//
//    return ADD64(x[7], LOAD(sha512_x1_p));
//}


_INLINE_ vec_t sha512_update_x_avx(vec_t x[8], const sha512_word_t* sha512_x1_p)
{
    vec_t t[2];
    vec_t s0;
    vec_t s1;

    // This function recieves 8 wide registers X[7:0]=q[15:0] and calculates:
    // s0 = sigma0(q[2:1])
    // s1 = sigma1(q[15:14])
    // q[1:0] += s0 + s1 + q[10:9]

    t[0] = ALIGNR8(x[1], x[0], 8); // q[2:1]
    t[1] = ALIGNR8(x[5], x[4], 8); // q[10:9]
    s0 = XOR(XOR(ROR64(t[0], sigma0_0), ROR64(t[0], sigma0_1)), SRL64(t[0], sigma0_2));
    s1 = XOR(XOR(ROR64(x[7], sigma1_0), ROR64(x[7], sigma1_1)), SRL64(x[7], sigma1_2));
    x[0] = ADD64(ADD64(ADD64(x[0], s1), s0), t[1]);

    rotate_x(x);

    return ADD64(x[7], LOAD(sha512_x1_p));
}

_INLINE_ void load_data(OUT vec_t x[MS_VEC_NUM],
    IN OUT sha512_msg_schedule_t* ms,
    IN const uint8_t* data)
{
    // 64 bits (8 bytes) swap masks
    const vec_t shuf_mask =
        _mm_setr_epi32(0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b);

    PRAGMA_LOOP_UNROLL_8

        for (size_t i = 0; i < MS_VEC_NUM; i++) {
            const size_t pos = WORDS_IN_VEC * i;

            x[i] = LOAD(&data[sizeof(vec_t) * i]);
            x[i] = SHUF8(x[i], shuf_mask);
            STORE(&ms->w[pos], ADD64(x[i], LOAD(&sha512_x1[pos])));
        }
}

_INLINE_ void rounds_0_63(sha512_state_t* cur_state,
    vec_t                  x[MS_VEC_NUM],
    sha512_msg_schedule_t* ms)
{
    // The first SHA512_BLOCK_WORDS_NUM entries of sha512_x1 were loaded in
    // load_data(...).
    size_t sha512_x1_idx = SHA512_BLOCK_WORDS_NUM;

    // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
    for (size_t i = 0; i < 4; i++) {

        PRAGMA_LOOP_UNROLL_8

            for (size_t j = 0; j < MS_VEC_NUM; j++) {
                const size_t pos = WORDS_IN_VEC * j;

                const vec_t y = sha512_update_x_avx(x, &sha512_x1[sha512_x1_idx]);

                sha_round(cur_state, ms->w[pos], 0);
                sha_round(cur_state, ms->w[pos + 1], 0);

                STORE(&ms->w[pos], y);
                sha512_x1_idx += WORDS_IN_VEC;
            }
    }
}

_INLINE_ void rounds_64_79(sha512_state_t* cur_state,
    const sha512_msg_schedule_t* ms)
{
    PRAGMA_LOOP_UNROLL_16

        for (size_t i = SHA512_FINAL_ROUND_START_IDX; i < SHA512_ROUNDS_NUM; i++) {
            sha_round(cur_state, ms->w[LSB4(i)], 0);
        }
}

void sha512_compress_x86_64_avx(sha512_state_t* state,
    const uint8_t* data,
    size_t          blocks_num)
{
    sha512_state_t        cur_state;
    sha512_msg_schedule_t ms;
    vec_t                 x[MS_VEC_NUM];
    while (blocks_num--) {
        my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
        load_data(x, &ms, data);
        data += SHA512_BLOCK_BYTE_LEN;

        rounds_0_63(&cur_state, x, &ms);
        rounds_64_79(&cur_state, &ms);
        accumulate_state(state, &cur_state);
    }

    secure_clean(&cur_state, sizeof(cur_state));
    secure_clean(&ms, sizeof(ms));
}