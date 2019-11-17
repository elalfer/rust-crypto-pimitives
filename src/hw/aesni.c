#include <immintrin.h>

#define LD8(R, O, P) \
    R ## 0 = O((P) + 0); \
    R ## 1 = O((P) + 1); \
    R ## 2 = O((P) + 2); \
    R ## 3 = O((P) + 3); \
    R ## 4 = O((P) + 4); \
    R ## 5 = O((P) + 5); \
    R ## 6 = O((P) + 6); \
    R ## 7 = O((P) + 7);

#define ST8(P, O, R) \
    O((P) + 0, R ## 0); \
    O((P) + 1, R ## 1); \
    O((P) + 2, R ## 2); \
    O((P) + 3, R ## 3); \
    O((P) + 4, R ## 4); \
    O((P) + 5, R ## 5); \
    O((P) + 6, R ## 6); \
    O((P) + 7, R ## 7);

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
        LD8(ct, _mm_loadu_si128, ((__m128i*)pt) + i);
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
        // Last round
        OP8(ct, _mm_aesenclast_si128, ct, _mm_loadu_si128( ((__m128i*)key) + rounds));
        // Store data
        ST8(((__m128i*)ct) + i, _mm_storeu_si128, ct);
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
        ct0 = _mm_aesenclast_si128( ct0, _mm_loadu_si128( ((__m128i*)key) + rounds));

        _mm_storeu_si128(((__m128i*)ct) + i, ct0);
    }
    
}

__attribute__((target("aes")))
void aesni_dec_ecb(char* pt, size_t rounds, const char* ct, size_t blocks, const char *key) {
    size_t i = 0;
    __m128i pt0, pt1, pt2, pt3, pt4, pt5, pt6, pt7; 

    // Unroll by 8
    for (; i < (blocks & (~7)); i+=8)
    {
        // Load plain text data
        LD8(pt, _mm_loadu_si128, ((__m128i*)ct) + i);
        // XOR with key 0
        OP8(pt, _mm_xor_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 0));
        // Run rounds
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 1));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 2));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 3));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 4));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 5));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 6));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 7));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 8));
        OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 10));
            OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 12));
                OP8(pt, _mm_aesenc_si128, pt, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Last round
        OP8(pt, _mm_aesenclast_si128, pt, _mm_loadu_si128( ((__m128i*)key) + rounds));
        // Store data
        ST8(((__m128i*)pt) + i, _mm_storeu_si128, pt);
    }
    
    // Finish tail
    for (; i < blocks; i++) {
        pt0 = _mm_loadu_si128(((__m128i*)ct) + i);

        pt0 = _mm_xor_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 0));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 1));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 2));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 3));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 4));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 5));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 6));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 7));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 8));
        pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 10));
            pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 12));
                pt0 = _mm_aesenc_si128(pt0, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Finish last round
        pt0 = _mm_aesenclast_si128( pt0, _mm_loadu_si128( ((__m128i*)key) + rounds));

        _mm_storeu_si128(((__m128i*)ct) + i, pt0);
    }
    
}

__attribute__((target("aes,avx512f,vaes")))
void vaesni_enc_ecb(char* ct, size_t rounds, const char* pt, size_t blocks, const char *key) {
    size_t i = 0;
    __m512i ct0, ct1, ct2, ct3, ct4, ct5, ct6, ct7; 
    __m128i ctv;

    // Unroll by 8
    for (; i < (blocks & (~31)); i+=32)
    {
        // Load plain text data
        LD8(ct, _mm512_loadu_si512, ((__m128i*)pt) + i);
        // XOR with key 0
        OP8(ct, _mm512_xor_si512, ct, _mm512_broadcast_i32x4(_mm_loadu_si128( ((__m128i*)key) + 0)));
        // Run rounds
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 1)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 2)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 3)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 4)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 5)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 6)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 7)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 8)));
        OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 9)));
        if (rounds > 10) {
            OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 10)));
            OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 11)));
            if (rounds > 12) {
                OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 12)));
                OP8(ct, _mm512_aesenc_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 13)));
            }
        }
        // Last round
        OP8(ct, _mm512_aesenclast_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + rounds)));
        // Store data
        ST8(((__m128i*)ct) + i, _mm512_storeu_si512, ct);
    }
    
    // Finish tail
    for (; i < blocks; i++) {
        ctv = _mm_loadu_si128(((__m128i*)pt) + i);

        ctv = _mm_xor_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 0));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 1));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 2));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 3));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 4));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 5));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 6));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 7));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 8));
        ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 10));
            ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 12));
                ctv = _mm_aesenc_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Finish last round
        ctv = _mm_aesenclast_si128( ctv, _mm_loadu_si128( ((__m128i*)key) + rounds));

        _mm_storeu_si128(((__m128i*)ct) + i, ctv);
    }
    
}

__attribute__((target("aes,avx512f,vaes")))
void vaesni_dec_ecb(char* ct, size_t rounds, const char* pt, size_t blocks, const char *key) {
    size_t i = 0;
    __m512i ct0, ct1, ct2, ct3, ct4, ct5, ct6, ct7; 
    __m128i ctv;

    // Unroll by 8
    for (; i < (blocks & (~31)); i+=32)
    {
        // Load plain text data
        LD8(ct, _mm512_loadu_si512, ((__m128i*)pt) + i);
        // XOR with key 0
        OP8(ct, _mm512_xor_si512, ct, _mm512_broadcast_i32x4(_mm_loadu_si128( ((__m128i*)key) + 0)));
        // Run rounds
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 1)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 2)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 3)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 4)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 5)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 6)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 7)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 8)));
        OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 9)));
        if (rounds > 10) {
            OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 10)));
            OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 11)));
            if (rounds > 12) {
                OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 12)));
                OP8(ct, _mm512_aesdec_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + 13)));
            }
        }
        // Last round
        OP8(ct, _mm512_aesdeclast_epi128, ct, _mm512_broadcast_i32x4( _mm_loadu_si128( ((__m128i*)key) + rounds)));
        // Store data
        ST8(((__m128i*)ct) + i, _mm512_storeu_si512, ct);
    }
    
    // Finish tail
    for (; i < blocks; i++) {
        ctv = _mm_loadu_si128(((__m128i*)pt) + i);

        ctv = _mm_xor_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 0));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 1));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 2));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 3));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 4));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 5));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 6));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 7));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 8));
        ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 9));
        if (rounds > 10) {
            ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 10));
            ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 11));
            if (rounds > 12) {
                ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 12));
                ctv = _mm_aesdec_si128(ctv, _mm_loadu_si128( ((__m128i*)key) + 13));
            }
        }
        // Finish last round
        ctv = _mm_aesdeclast_si128( ctv, _mm_loadu_si128( ((__m128i*)key) + rounds));

        _mm_storeu_si128(((__m128i*)ct) + i, ctv);
    }
    
}
