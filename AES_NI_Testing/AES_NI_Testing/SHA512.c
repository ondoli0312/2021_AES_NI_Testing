#include "avx2_defs.h"
#include "sha512_defs.h"
#include <assert.h>
#include "constant.h"
#define SHA512_WORD_BIT_LEN (8 * sizeof(sha512_word_t))
#define MS_VEC_NUM           ((2 * SHA512_BLOCK_BYTE_LEN) / sizeof(vec_t))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha512_word_t))
#define WORDS_IN_VEC         (sizeof(vec_t) / sizeof(sha512_word_t))

ALIGN(64) const sha512_word_t sha512_x2[2 * SHA512_ROUNDS_NUM] = {
  DUP2(K512_0, K512_1),   DUP2(K512_2, K512_3),   DUP2(K512_4, K512_5),
  DUP2(K512_6, K512_7),   DUP2(K512_8, K512_9),   DUP2(K512_10, K512_11),
  DUP2(K512_12, K512_13), DUP2(K512_14, K512_15), DUP2(K512_16, K512_17),
  DUP2(K512_18, K512_19), DUP2(K512_20, K512_21), DUP2(K512_22, K512_23),
  DUP2(K512_24, K512_25), DUP2(K512_26, K512_27), DUP2(K512_28, K512_29),
  DUP2(K512_30, K512_31), DUP2(K512_32, K512_33), DUP2(K512_34, K512_35),
  DUP2(K512_36, K512_37), DUP2(K512_38, K512_39), DUP2(K512_40, K512_41),
  DUP2(K512_42, K512_43), DUP2(K512_44, K512_45), DUP2(K512_46, K512_47),
  DUP2(K512_48, K512_49), DUP2(K512_50, K512_51), DUP2(K512_52, K512_53),
  DUP2(K512_54, K512_55), DUP2(K512_56, K512_57), DUP2(K512_58, K512_59),
  DUP2(K512_60, K512_61), DUP2(K512_62, K512_63), DUP2(K512_64, K512_65),
  DUP2(K512_66, K512_67), DUP2(K512_68, K512_69), DUP2(K512_70, K512_71),
  DUP2(K512_72, K512_73), DUP2(K512_74, K512_75), DUP2(K512_76, K512_77),
  DUP2(K512_78, K512_79),
};

_INLINE_ void load_data(vec_t x[MS_VEC_NUM], sha512_msg_schedule_t* ms, sha512_word_t t2[SHA512_ROUNDS_NUM], const uint8_t* data)
{
    // 64 bits (8 bytes) swap masks
    const vec_t shuf_mask =
        _mm256_set_epi64x(DUP2(0x08090a0b0c0d0e0f, 0x0001020304050607));

    PRAGMA_LOOP_UNROLL_8

        for (size_t i = 0; i < MS_VEC_NUM; i++) {
            const size_t pos0 = (sizeof(vec_t) / 2) * i;
            const size_t pos1 = pos0 + SHA512_BLOCK_BYTE_LEN;

            LOADU2(&data[pos1], &data[pos0], x[i]);
            x[i] = SHUF8(x[i], shuf_mask);
            vec_t y = ADD64(x[i], LOAD(&sha512_x2[4 * i]));
            STOREU2(&t2[2 * i], &ms->w[2 * i], y);
        }
}

_INLINE_ void rotate_x(vec_t x[8])
{
    const vec_t tmp = x[0];

    for (size_t i = 0; i < 7; i++) {
        x[i] = x[i + 1];
    }

    x[7] = tmp;
}

_INLINE_ vec_t sha512_update_x_avx(vec_t x[8], const sha512_word_t* sha512_x1_p)
{
    vec_t t[4];

    t[0] = ALIGNR8(x[1], x[0], 8);                      // q[2:1]
    t[3] = ALIGNR8(x[5], x[4], 8);                      // q[10:9]
    t[2] = SRL64(t[0], sigma0_0);                       // q[2:1] >> s0[0]
    x[0] = ADD64(x[0], t[3]);                           // q[1:0] + q[10:9]
    t[3] = SRL64(t[0], sigma0_2);                       // q[2:1] >> s0[2]
    t[1] = SLL64(t[0], SHA512_WORD_BIT_LEN - sigma0_1); // q[2:1] << (64 - s0[1])
    t[0] = _mm256_xor_si256(t[3], t[2]);                // (q[2:1] >> s0[2]) ^
                                                        // (q[2:1] >> s0[0])
    t[2] = SRL64(t[2], sigma0_1 - sigma0_0);            // q[2:1] >> s0[1]
    t[0] = _mm256_xor_si256(t[0], t[1]);                // (q[2:1] >> s0[2]) ^
                                                        //  (q[2:1] >> s0[0]) ^
                                                        //  q[2:1] << (64 - s0[1])
    t[1] = SLL64(t[1], sigma0_1 - sigma0_0);            // q[2:1] << (64 - s0[0])
    t[0] = _mm256_xor_si256(t[2], t[1]);                // sigma1(q[2:1])
    t[3] = SRL64(x[7], sigma1_2);                       // q[15:14] >> s1[2]
    t[2] = SLL64(x[7], SHA512_WORD_BIT_LEN - sigma1_1); // q[15:14] >> (64 - s1[1])
    x[0] = ADD64(x[0], t[0]);                           // q[1:0] + sigma0(q[2:1])
    t[1] = SRL64(x[7], sigma1_0);                       // q[15:14] >> s1[0]
    t[3] = _mm256_xor_si256(t[3], t[2]);                // q[15:14] >> s1[2] ^
                                                        //  q[15:14] >> (64 - s1[1])
    t[2] = SLL64(t[2], sigma1_1 - sigma1_0);            // q[15:14] >> (64 - s1[0])
    t[3] = _mm256_xor_si256(t[3], t[1]);                // q[15:14] >> s1[2] ^
                                                        //  q[15:14] >> (64 - s1[1] ^
                                                        //  q[15:14] >> s1[0]
    t[1] = SRL64(t[1], sigma1_1 - sigma1_0);            // q[15:14] >> s1[1]
    t[3] = _mm256_xor_si256(t[3], t[2]);                // sigma1(q[15:14])

    // q[1:0] + q[10:9] + sigma1(q[15:14]) + sigma0(q[2:1])
    x[0] = ADD64(x[0], t[3]);

    rotate_x(x);

    return ADD64(x[7], LOAD(sha512_x1_p));
}


_INLINE_ void rounds_0_63(sha512_state_t* cur_state,
    vec_t                  x[MS_VEC_NUM],
    sha512_msg_schedule_t* ms,
    sha512_word_t          t2[SHA512_ROUNDS_NUM])
{
    // The first SHA512_BLOCK_WORDS_NUM entries of sha512_x1 were loaded in
    // load_data(...).
    size_t sha512_x1_idx = 2 * SHA512_BLOCK_WORDS_NUM;

    // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
    for (size_t i = 1; i < 5; i++) {

        PRAGMA_LOOP_UNROLL_8

            for (size_t j = 0; j < 8; j++) {
                const size_t pos = WORDS_IN_128_BIT_VEC * j;

                const vec_t y = sha512_update_x_avx(x, &sha512_x2[sha512_x1_idx]);

                sha_round(cur_state, ms->w[pos], 0);
                sha_round(cur_state, ms->w[pos + 1], 0);
                STOREU2(&t2[(16 * i) + pos], &ms->w[pos], y);
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

_INLINE_ void process_second_block(sha512_state_t* cur_state,
    const sha512_word_t t2[SHA512_ROUNDS_NUM])
{
    PRAGMA_LOOP_UNROLL_80

        for (size_t i = 0; i < SHA512_ROUNDS_NUM; i++) {
            sha_round(cur_state, t2[i], 0);
        }
}

void sha512_compress_x86_64_avx2(sha512_state_t* state,
    const uint8_t* data,
    size_t          blocks_num)
{
    ALIGN(64) sha512_msg_schedule_t ms;
    ALIGN(64) sha512_word_t         t2[SHA512_ROUNDS_NUM];
    sha512_state_t                  cur_state;
    vec_t                           x[MS_VEC_NUM];

    if (LSB1(blocks_num)) {
        sha512_compress_x86_64_avx(state, data, 1);
        data += SHA512_BLOCK_BYTE_LEN;
        blocks_num--;
    }

    // Process two blocks in parallel
    // Here blocks_num is even
    for (size_t b = blocks_num; b != 0; b -= 2) {
        my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
        load_data(x, &ms, t2, data);
        data += 2 * SHA512_BLOCK_BYTE_LEN;

        // First block
        rounds_0_63(&cur_state, x, &ms, t2);
        rounds_64_79(&cur_state, &ms);
        accumulate_state(state, &cur_state);

        // Second block
        my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
        process_second_block(&cur_state, t2);
        accumulate_state(state, &cur_state);
    }

    secure_clean(&cur_state, sizeof(cur_state));
    secure_clean(&ms, sizeof(ms));
    secure_clean(t2, sizeof(t2));
}
/////////////////////////////////////////////////////////////////////////////////////////

#define LAST_BLOCK_BYTE_LEN (2 * SHA512_BLOCK_BYTE_LEN)

typedef struct sha512_hash_s {
    ALIGN(64) sha512_state_t state;
    uint64_t len;

    ALIGN(64) uint8_t data[LAST_BLOCK_BYTE_LEN];

    sha512_word_t rem;
} sha512_ctx_t;

_INLINE_ void sha512_init(OUT sha512_ctx_t* ctx)
{
    ctx->state.w[0] = UINT64_C(0x6a09e667f3bcc908);
    ctx->state.w[1] = UINT64_C(0xbb67ae8584caa73b);
    ctx->state.w[2] = UINT64_C(0x3c6ef372fe94f82b);
    ctx->state.w[3] = UINT64_C(0xa54ff53a5f1d36f1);
    ctx->state.w[4] = UINT64_C(0x510e527fade682d1);
    ctx->state.w[5] = UINT64_C(0x9b05688c2b3e6c1f);
    ctx->state.w[6] = UINT64_C(0x1f83d9abfb41bd6b);
    ctx->state.w[7] = UINT64_C(0x5be0cd19137e2179);
}

_INLINE_ void sha512_compress(IN OUT sha512_ctx_t* ctx,
    IN const uint8_t* data,
    IN const size_t   blocks_num)
{
    assert((ctx != NULL) && (data != NULL));

    // OpenSSL code can crash without this check
    if (blocks_num == 0) {
        return;
    }
    sha512_compress_x86_64_avx2(&ctx->state, data, blocks_num);
}

_INLINE_ void sha512_update(IN OUT sha512_ctx_t* ctx,
    IN const uint8_t* data,
    IN size_t         byte_len)
{
    // On exiting this function ctx->rem < SHA512_BLOCK_BYTE_LEN

    assert((ctx != NULL) && (data != NULL));

    if (byte_len == 0) {
        return;
    }

    // Accumulate the overall size
    ctx->len += byte_len;

    // Less than a block. Store the data in a temporary buffer
    if ((ctx->rem != 0) && (ctx->rem + byte_len < SHA512_BLOCK_BYTE_LEN)) {
        my_memcpy(&ctx->data[ctx->rem], data, byte_len);
        ctx->rem += byte_len;
        return;
    }

    // Complete and compress a previously stored block
    if (ctx->rem != 0) {
        const size_t clen = SHA512_BLOCK_BYTE_LEN - ctx->rem;
        my_memcpy(&ctx->data[ctx->rem], data, clen);
        sha512_compress(ctx, ctx->data, 1);

        data += clen;
        byte_len -= clen;

        ctx->rem = 0;
        secure_clean(ctx->data, SHA512_BLOCK_BYTE_LEN);
    }

    // Compress full blocks
    if (byte_len >= SHA512_BLOCK_BYTE_LEN) {
        const size_t blocks_num = (byte_len >> 7);
        const size_t full_blocks_byte_len = (blocks_num << 7);
        sha512_compress(ctx, data, blocks_num);
        data += full_blocks_byte_len;
        byte_len -= full_blocks_byte_len;
    }

    // Store the reminder
    my_memcpy(ctx->data, data, byte_len);
    ctx->rem = byte_len;
}

_INLINE_ void sha512_final(OUT uint8_t* dgst, IN OUT sha512_ctx_t* ctx)
{
    assert((ctx != NULL) && (dgst != NULL));
    assert(ctx->rem < SHA512_BLOCK_BYTE_LEN);

    // Byteswap the length in bits of the hashed message
    const uint64_t bswap_len = bswap_64(8 * ctx->len);
    const size_t   last_block_num = (ctx->rem < 112) ? 1 : 2;
    const size_t   last_qw_pos =
        (last_block_num * SHA512_BLOCK_BYTE_LEN) - sizeof(bswap_len);

    ctx->data[ctx->rem++] = SHA512_MSG_END_SYMBOL;

    // Reset the rest of the data buffer
    my_memset(&ctx->data[ctx->rem], 0, sizeof(ctx->data) - ctx->rem);
    my_memcpy(&ctx->data[last_qw_pos], (const uint8_t*)&bswap_len,
        sizeof(bswap_len));

    // Compress the final block
    sha512_compress(ctx, ctx->data, last_block_num);
    // This implementation assumes running on a Little endian machine
    ctx->state.w[0] = bswap_64(ctx->state.w[0]);
    ctx->state.w[1] = bswap_64(ctx->state.w[1]);
    ctx->state.w[2] = bswap_64(ctx->state.w[2]);
    ctx->state.w[3] = bswap_64(ctx->state.w[3]);
    ctx->state.w[4] = bswap_64(ctx->state.w[4]);
    ctx->state.w[5] = bswap_64(ctx->state.w[5]);
    ctx->state.w[6] = bswap_64(ctx->state.w[6]);
    ctx->state.w[7] = bswap_64(ctx->state.w[7]);
    my_memcpy(dgst, ctx->state.w, SHA512_HASH_BYTE_LEN);
    secure_clean(ctx, sizeof(*ctx));
}

void sha512(OUT uint8_t* dgst,
    IN const uint8_t* data,
    IN const size_t     byte_len)
{
    assert((data != NULL) || (dgst != NULL));

    sha512_ctx_t ctx = { 0 };
    sha512_init(&ctx);
    sha512_update(&ctx, data, byte_len);
    sha512_final(dgst, &ctx);
}