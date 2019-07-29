#pragma once

#include <cstdint>
#include <vector>
#include <wmmintrin.h>

namespace {

// via
//! \sa https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
//! \sa https://gist.github.com/acapola/d5b940da024080dfaf5f
inline __m128i AES_128_ASSIST( __m128i temp1, __m128i temp2 ) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32( temp2, 0xff );
    temp3 = _mm_slli_si128( temp1, 0x4 );
    temp1 = _mm_xor_si128( temp1, temp3 );
    temp3 = _mm_slli_si128( temp3, 0x4 );
    temp1 = _mm_xor_si128( temp1, temp3 );
    temp3 = _mm_slli_si128( temp3, 0x4 );
    temp1 = _mm_xor_si128( temp1, temp3 );
    temp1 = _mm_xor_si128( temp1, temp2 );
    return temp1;
}

std::vector<__m128i> AES_128_Key_Expansion( const __m128i* userkey ) {
    std::vector<__m128i> key( 20 );

    __m128i temp1, temp2;
    temp1 = _mm_loadu_si128( userkey );
    key[0] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x1 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[1] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x2 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[2] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x4 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[3] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x8 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[4] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x10 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[5] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x20 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[6] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x40 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[7] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x80 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[8] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x1b );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[9] = temp1;

    temp2 = _mm_aeskeygenassist_si128( temp1, 0x36 );
    temp1 = AES_128_ASSIST( temp1, temp2 );
    key[10] = temp1;

    key[11] = _mm_aesimc_si128( key[9] );
    key[12] = _mm_aesimc_si128( key[8] );
    key[13] = _mm_aesimc_si128( key[7] );
    key[14] = _mm_aesimc_si128( key[6] );
    key[15] = _mm_aesimc_si128( key[5] );
    key[16] = _mm_aesimc_si128( key[4] );
    key[17] = _mm_aesimc_si128( key[3] );
    key[18] = _mm_aesimc_si128( key[2] );
    key[19] = _mm_aesimc_si128( key[1] );

    return key;
}

}

namespace aesni {

const size_t blockSize = 16;
const size_t rounds = 10;

inline void encryptAES128ECB( const uint8_t* in, uint8_t* out, const size_t length, const uint8_t* userkey ) {
    size_t j = 0;
    size_t blocks = length / 16;
    __m128i tmp;

    std::vector<__m128i> key = AES_128_Key_Expansion( ( __m128i* )userkey );

    for( size_t i = 0; i < blocks; ++i ) {
        tmp = _mm_loadu_si128( &( ( __m128i* )in )[i] );
        tmp = _mm_xor_si128( tmp, key[0] );

        for( j = 1; j < rounds; j++ ) {
            tmp = _mm_aesenc_si128( tmp, key[j] );
        }

        tmp = _mm_aesenclast_si128( tmp, key[j] );
        _mm_storeu_si128( &( ( __m128i* )out )[i], tmp );
    }
}

inline void decryptAES128ECB( const uint8_t* in, uint8_t* out, const size_t length, const uint8_t* userkey ) {
    size_t j = 0;
    size_t blocks = length / 16;
    __m128i tmp;

    std::vector<__m128i> key = AES_128_Key_Expansion( ( __m128i* )userkey );

    for( size_t i = 0; i < blocks; ++i ) {
        tmp = _mm_loadu_si128( &( ( __m128i* )in )[i] );
        tmp = _mm_xor_si128( tmp, key[10] );

        for( j = 1; j < rounds; j++ ) {
            tmp = _mm_aesdec_si128( tmp, key[10 + j] );
        }

        tmp = _mm_aesdeclast_si128( tmp, key[0] );
        _mm_storeu_si128( &( ( __m128i* )out )[i], tmp );
    }
}

}
