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

template<size_t T>
using Magic = std::array<uint32_t, T>;

template<class Container = std::vector<uint8_t>, size_t T, bool reverse>
inline Container magicsToSha( const Magic<T>& magics ) {

    Container res( T * 4, 0 );

    for( size_t i = 0; i < magics.size(); ++i ) {
        if constexpr( reverse ) {
            uint32_t tmp = endian_reverse( magics[i] );
            memcpy( res.data() + 4 * i, &tmp, 4 );
        } else {
            memcpy( res.data() + 4 * i, &magics[i], 4 );
        }
    }

    return res;
}

template<class Container = std::vector<uint8_t>, size_t T, bool reverse>
inline Magic<T> shaToMagics( const Container& in ) {

    Magic<T> magics;

    for( size_t i = 0; i < magics.size(); ++i ) {
        memcpy( &magics[i], in.data() + 4 * i, 4 );

        if constexpr( reverse ) {
            magics[i] = endian_reverse( magics[i] );
        }
    }

    return magics;
}

template<class Container = std::vector<uint8_t>, bool reverse>
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
    if constexpr( reverse ) {
        bits = endian_reverse( bits );
    }

    memcpy( &padding[fill - 8], &bits, 8 );

    return padding;
}

const Magic<5> SHA1_MAGICS = { 0x67452301,
                               0xEFCDAB89,
                               0x98BADCFE,
                               0x10325476,
                               0xC3D2E1F0
                             };

//! \sa https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
template<class Container = std::vector<uint8_t>>
Container sha1( const Container& in, Magic<5> magics = SHA1_MAGICS, size_t offset = 0 ) {
    static_assert( sizeof( typename Container::value_type ) == 1, "Container type must be 8 bit" );

    size_t bytes = in.size();
    Container work = in + sha1MDPadding<Container, true>( bytes );
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

        for( unsigned long i = 0; i < 80; ++i ) {
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

    Container res = magicsToSha<Container, 5, true>( magics );
    return res;
}

const Magic<4> MD4_MAGICS = { 0x67452301,
                              0xefcdab89,
                              0x98badcfe,
                              0x10325476,
                            };

//! \sa https://tools.ietf.org/html/rfc1320
template<class Container = std::vector<uint8_t>>
Container md4( const Container& in, Magic<4> magics = MD4_MAGICS, size_t offset = 0 ) {

    size_t bytes = in.size();
    Container work = in + sha1MDPadding<Container, false>( bytes );
    size_t size = work.size();

    std::vector<uint32_t> X( 80 );

    uint32_t A = magics[0];
    uint32_t B = magics[1];
    uint32_t C = magics[2];
    uint32_t D = magics[3];

    auto F = []( const uint32_t& X, const uint32_t& Y, const uint32_t& Z ) { return ( X & Y ) | ( ~X & Z ); };
    auto G = []( const uint32_t& X, const uint32_t& Y, const uint32_t& Z ) { return ( X & Y ) | ( X & Z ) | ( Y & Z );};
    auto H = []( const uint32_t& X, const uint32_t& Y, const uint32_t& Z ) { return X ^ Y ^ Z; };

    for( size_t pos = offset; pos < size; pos += 64 ) {
        // copy work into first 16 words as big endian
        memcpy( X.data(), &work[pos], 64 );

        // and convert to little endian
        //        for( size_t i = 0; i < 16; ++i ) {
        //            X[i] = endian_reverse( X[i] );
        //        }

        uint32_t AA = A;
        uint32_t BB = B;
        uint32_t CC = C;
        uint32_t DD = D;

        // round 1
#define OP(a,b,c,d,k,s) a = rotL<s>( a + F( b, c, d ) + X[k] )
        OP( A, B, C, D,  0,  3 ); OP( D, A, B, C,  1,  7 ); OP( C, D, A, B,  2, 11 ); OP( B, C, D, A,  3, 19 );
        OP( A, B, C, D,  4,  3 ); OP( D, A, B, C,  5,  7 ); OP( C, D, A, B,  6, 11 ); OP( B, C, D, A,  7, 19 );
        OP( A, B, C, D,  8,  3 ); OP( D, A, B, C,  9,  7 ); OP( C, D, A, B, 10, 11 ); OP( B, C, D, A, 11, 19 );
        OP( A, B, C, D, 12,  3 ); OP( D, A, B, C, 13,  7 ); OP( C, D, A, B, 14, 11 ); OP( B, C, D, A, 15, 19 );
#undef OP

        // round 2
#define OP(a,b,c,d,k,s) a = rotL<s>( a + G( b, c, d ) + X[k] + 0x5A827999 )
        OP( A, B, C, D,  0,  3 ); OP( D, A, B, C,  4,  5 ); OP( C, D, A, B,  8,  9 ); OP( B, C, D, A, 12, 13 );
        OP( A, B, C, D,  1,  3 ); OP( D, A, B, C,  5,  5 ); OP( C, D, A, B,  9,  9 ); OP( B, C, D, A, 13, 13 );
        OP( A, B, C, D,  2,  3 ); OP( D, A, B, C,  6,  5 ); OP( C, D, A, B, 10,  9 ); OP( B, C, D, A, 14, 13 );
        OP( A, B, C, D,  3,  3 ); OP( D, A, B, C,  7,  5 ); OP( C, D, A, B, 11,  9 ); OP( B, C, D, A, 15, 13 );
#undef OP

        // round 3
#define OP(a,b,c,d,k,s) a = rotL<s>( a + H( b, c, d ) + X[k] + 0x6ED9EBA1 )
        OP( A, B, C, D,  0,  3 ); OP( D, A, B, C,  8,  9 ); OP( C, D, A, B,  4, 11 ); OP( B, C, D, A, 12, 15 );
        OP( A, B, C, D,  2,  3 ); OP( D, A, B, C, 10,  9 ); OP( C, D, A, B,  6, 11 ); OP( B, C, D, A, 14, 15 );
        OP( A, B, C, D,  1,  3 ); OP( D, A, B, C,  9,  9 ); OP( C, D, A, B,  5, 11 ); OP( B, C, D, A, 13, 15 );
        OP( A, B, C, D,  3,  3 ); OP( D, A, B, C, 11,  9 ); OP( C, D, A, B,  7, 11 ); OP( B, C, D, A, 15, 15 );
#undef OP

        A += AA;
        B += BB;
        C += CC;
        D += DD;
    }

    magics[0] = A;
    magics[1] = B;
    magics[2] = C;
    magics[3] = D;

    Container res = magicsToSha<Container, 4, false>( magics );
    return res;
}

}
