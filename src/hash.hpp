#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

namespace hash {

template<uint32_t T>
inline uint32_t rotL( const uint32_t& in ) {
    return in << T | in >> ( 32 - T );
}

template <class T = size_t>
inline bool between( const T& a, const T& b, const T& c ) {
    return a <= b && b <= c;
}

// from
// boost/endian/detail/endian_reverse.hpp
inline uint32_t endian_reverse( uint32_t x ) {
    uint32_t step16 = x << 16 | x >> 16;
    return ( ( step16 << 8 ) & 0xff00ff00 ) | ( ( step16 >> 8 ) & 0x00ff00ff );
}

inline uint64_t endian_reverse( uint64_t x ) {
    uint64_t step32 = x << 32 | x >> 32;
    uint64_t step16 = ( step32 & 0x0000FFFF0000FFFFULL ) << 16 | ( step32 & 0xFFFF0000FFFF0000ULL ) >> 16;
    return ( step16 & 0x00FF00FF00FF00FFULL ) << 8 | ( step16 & 0xFF00FF00FF00FF00ULL ) >> 8;
}

using Magic = std::array<uint32_t, 5>;

template<class Container = std::vector<uint8_t>>
inline Container magicsToSha( const Magic& magics ) {

    Container res( 20, 0 );

    for( size_t i = 0; i < 5; ++i ) {
        uint32_t tmp = endian_reverse( magics[i] );
        memcpy( res.data() + 4 * i, &tmp, 4 );
    }

    return res;
}

template<class Container = std::vector<uint8_t>>
inline Magic shaToMagics( const Container& in ) {

    Magic magics;

    for( size_t i = 0; i < 5; ++i ) {
        memcpy( &magics[i], in.data() + 4 * i, 4 );
        magics[i] = endian_reverse( magics[i] );
    }

    return magics;
}

template<class Container = std::vector<uint8_t>>
Container sha1MDPadding( const size_t& bytes ) {
    uint64_t bits = bytes * 8;

    // pad with zeros
    size_t fill = 64 - bytes % 64;

    // at least 9 bytes for parity bit and length
    if( fill < 9 ) { fill += 64; }

    Container padding( fill, 0 );

    // parity bit, always 1 for byte container
    padding[0] = 0x80;

    // put size in big endian at end
    uint64_t bitsBE = endian_reverse( bits );
    memcpy( &padding[fill - 8], &bitsBE, 8 );

    return padding;
}

const Magic SHA1_MAGICS = { 0x67452301,
                            0xEFCDAB89,
                            0x98BADCFE,
                            0x10325476,
                            0xC3D2E1F0
                          };

//! \sa https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
template<class Container = std::vector<uint8_t>>
Container sha1( const Container& in, Magic magics = SHA1_MAGICS, size_t offset = 0 ) {
    static_assert( sizeof( typename Container::value_type ) == 1, "Container type must be 8 bit" );

    size_t bytes = in.size();
    Container work = in + sha1MDPadding<Container>( bytes );
    size_t size = work.size();

    std::vector<uint32_t> w( 80 );

    for( size_t pos = offset; pos < size; pos += 64 ) {
        // copy work into first 16 words as big endian
        memcpy( w.data(), &work[pos], 64 );

        // and convert to little endian
        for( size_t i = 0; i < 16; ++i ) {
            w[i] = endian_reverse( w[i] );
        }

        for( size_t i = 16; i < 80; ++i ) {
            w[i] = rotL<1>( w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16] );
        }

        uint32_t a = magics[0];
        uint32_t b = magics[1];
        uint32_t c = magics[2];
        uint32_t d = magics[3];
        uint32_t e = magics[4];
        uint32_t f = 0;
        uint32_t k = 0;

        for( size_t i = 0; i < 80; ++i ) {
            if( between( 0ul, i, 19ul ) ) {
                f = ( b & c ) | ( ( ~ b ) & d );
                k = 0x5A827999;
            } else if( between( 20ul, i, 39ul ) ) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if( between( 40ul, i, 59ul ) ) {
                f = ( b & c ) | ( b & d ) | ( c & d );
                k = 0x8F1BBCDC;
            } else if( between( 60ul, i, 79ul ) ) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotL<5>( a ) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotL<30>( b );
            b = a;
            a = temp;
        }

        magics[0] += a;
        magics[1] += b;
        magics[2] += c;
        magics[3] += d;
        magics[4] += e;
    }

    Container res = magicsToSha( magics );
    return res;
}

}
