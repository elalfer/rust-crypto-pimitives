#include <immintrin.h>

#define OP8(R, O, S, K) \
    R ## 0 = O(S ## 0, K); \
    R ## 1 = O(S ## 1, K); \
    R ## 2 = O(S ## 2, K); \
    R ## 3 = O(S ## 3, K); \
    R ## 4 = O(S ## 4, K); \
    R ## 5 = O(S ## 5, K); \
    R ## 6 = O(S ## 6, K); \
    R ## 7 = O(S ## 7, K);

__attribute__((target("aes")))
void aesni_enc_ecb(char* ct, size_t rounds, const char* pt, size_t blocks, const char *key) {
    size_t i = 0;
    __m128i ct0, ct1, ct2, ct3, ct4, ct5, ct6, ct7; 

    // Unroll by 8
    for (; i < (blocks & (~7)); i+=8)
    {
        // Load plain text data
        ct0 = _mm_loadu_si128(((__m128i*)pt) + i + 0);
        ct1 = _mm_loadu_si128(((__m128i*)pt) + i + 1);
        ct2 = _mm_loadu_si128(((__m128i*)pt) + i + 2);
        ct3 = _mm_loadu_si128(((__m128i*)pt) + i + 3);
        ct4 = _mm_loadu_si128(((__m128i*)pt) + i + 4);
        ct5 = _mm_loadu_si128(((__m128i*)pt) + i + 5);
        ct6 = _mm_loadu_si128(((__m128i*)pt) + i + 6);
        ct7 = _mm_loadu_si128(((__m128i*)pt) + i + 7);

        // XOR with key 0
        OP8(ct, _mm_xor_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 0));
        // Run rounds
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 1));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 2));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 3));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 4));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 5));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 6));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 7));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 8));
        OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 10));
            OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 12));
                OP8(ct, _mm_aesenc_si128, ct, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Finish last round
        OP8(ct, _mm_aesenclast_si128, ct, _mm_loadu_si128( ((__m128i*)key) + rounds));

        // Store data
        _mm_storeu_si128(((__m128i*)ct) + i + 0, ct0);
        _mm_storeu_si128(((__m128i*)ct) + i + 1, ct1);
        _mm_storeu_si128(((__m128i*)ct) + i + 2, ct2);
        _mm_storeu_si128(((__m128i*)ct) + i + 3, ct3);
        _mm_storeu_si128(((__m128i*)ct) + i + 4, ct4);
        _mm_storeu_si128(((__m128i*)ct) + i + 5, ct5);
        _mm_storeu_si128(((__m128i*)ct) + i + 6, ct6);
        _mm_storeu_si128(((__m128i*)ct) + i + 7, ct7);
    }
    
    // Finish tail
    for (; i < blocks; i++) {
        ct0 = _mm_loadu_si128(((__m128i*)pt) + i);

        ct0 = _mm_xor_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 0));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 1));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 2));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 3));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 4));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 5));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 6));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 7));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 8));
        ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 10));
            ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 12));
                ct0 = _mm_aesenc_si128(ct0, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Finish last round
        OP8(ct, _mm_aesenclast_si128, ct, _mm_loadu_si128( ((__m128i*)key) + rounds));

        _mm_storeu_si128(((__m128i*)ct) + i, ct0);
    }
    
}

