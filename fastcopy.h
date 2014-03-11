#ifndef _FASTCOPY_H_
#define _FASTCOPY_H_

//#include  <mmintrin.h> /* MMX */
//#include <xmmintrin.h> /* SSE */
//#include <emmintrin.h> /* SSE2 */
//#include <pmmintrin.h> /* SSE3 */
//#include <tmmintrin.h> /* SSSE3 */
//#include <smmintrin.h> /* SSSE4.1 */
//#include <nmmintrin.h> /* SSSE4.2 */
//#include <ammintrin.h> /* SSSE4A */
//#include <immintrin.h> /* AVX */

#include <x86intrin.h> /* includes SSE/AVX/3dnow! headers
                        * according to compiler flags */

/*
 * Aligned copy primitives
 */
#define _cpy2a(dst, src) *((uint16_t *) (dst)) = *((uint16_t *) (src))
#define _cpy4a(dst, src) *((uint32_t *) (dst)) = *((uint32_t *) (src))
#define _cpy8a(dst, src) *((uint64_t *) (dst)) = *((uint64_t *) (src))
#define _cpy16a(dst, src)                                       \
    do {                                                        \
        __m128i reg = _mm_load_si128((__m128i *) (src));        \
        _mm_store_si128((__m128i *) (dst), xmm);                \
    } while(0)

#ifdef __AVX__
#define _cpy32a(dst, src)                                       \
    do {                                                        \
        __m256i reg = _mm256_load_si256((__m256i *) (src));     \
        _mm256_store_si256((__m256 *) (dst), xmm);              \
    } while(0)
#else
#define _cpy32a(dst, src)                                       \
    do {                                                        \
        __m128i reg0 = _mm_load_si128((__m128i *) (src));       \
        __m128i reg1 = _mm_load_si128(++((__m128i *) (src)));   \
        _mm_store_si128((__m128i *) (dst), reg0);               \
        _mm_store_si128(++((__m128i *) (dst)), reg1);           \
    } while(0)
#endif

/*
 * Unaligned copy primitives
 */
#define _cpy1u(dst, src) *( (uint8_t *) (dst)) = *( (uint8_t *) (src))
#define _cpy16u(dst, src)                                       \
    do {                                                        \
        __m128i reg = _mm_loadu_si128((__m128i *) (src));       \
        _mm_storeu_si128((__m128i *) (dst), xmm);               \
    } while(0)

#ifdef __AVX__
#define _cpy32u(dst, src)                                       \
    do {                                                        \
        __m256i reg = _mm256_loadu_si256((__m256i *) (src));    \
        _mm256_storeu_si256((__m256 *) (dst), xmm);             \
    } while(0)
#else
#define _cpy32u(dst, src)                                               \
    do {                                                                \
        __m128i reg0 = _mm_loadu_si128((__m128i *) (src));              \
        __m128i reg1 = _mm_loadu_si128((__m128i *) ((uint8_t *)(src)) + 16); \
        _mm_storeu_si128((__m128i *) (dst), reg0);                      \
        _mm_storeu_si128((__m128i *) ((uint8_t *) (dst) + 16), reg1);   \
    } while(0)
#endif

static inline void *fcpy16_32(void *dst, void *src, size_t len)
{
    _cpy16u((uint8_t *) dst,
            (uint8_t *) src);
    _cpy16u(((uint8_t *) dst) + (len - 16),
            ((uint8_t *) src) + (len - 16));
}

static inline void *fcpy32_64(void *dst, void *src, size_t len)
{
    _cpy32u((uint8_t *) dst,
            (uint8_t *) src);
    _cpy32u(((uint8_t *) dst) + (len - 32),
            ((uint8_t *) src) + (len - 32));
}

#define fcpy(dst, src, len)                   \
    __builtin_constant_p(len) ?               \
    __builtin_memcpy((dst), (src), (len)) :   \
    _do_fcpy((dst), (src), (len))

static inline void *_do_fcpy(void *dst, void *src, size_t len)
{
    if (len <= 16)
        memcpy(dst, src, len);
    else if(len <  32)
        fcpy16_32(dst, src, len);
    else if(len == 32)
        _cpy32u(dst, src, len);
    else if(len <  64)
        fcpy32_64(dst, src, len);
    else if(len == 64)
        _cpy64u(dst, src, len);
    else
        memcpy(dst, src, len); /* slow path */

    return dst;
}

#endif /* _FASTCOPY_H_ */
