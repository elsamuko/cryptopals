#include "converter.hpp"

#include <map>

namespace  {
uint8_t parseHex( const char& hex ) {
    if( hex >= '0' && hex <= '9' ) {
        return static_cast<uint8_t>( hex - '0' );
    }

    if( hex >= 'a' && hex <= 'f' ) {
        return static_cast<uint8_t>( 10 + hex - 'a' );
    }

    if( hex >= 'A' && hex <= 'F' ) {
        return static_cast<uint8_t>( 10 + hex - 'A' );
    }

    return 0;
}
}

Bytes converter::hexToBinary( const std::string& hex ) {
    size_t size   = hex.size() / 2;
    Bytes binary( size, 0 );

    for( size_t i = 0; i < size; ++i ) {
        uint8_t higher = static_cast<uint8_t>( parseHex( hex[2 * i + 0] ) );
        uint8_t lower  = static_cast<uint8_t>( parseHex( hex[2 * i + 1] ) );
        binary[i] =  lower + 16 * higher;
    }

    if( hex.size() % 2 ) {
        uint8_t lower  = static_cast<uint8_t>( parseHex( hex.back() ) );
        binary.emplace_back( lower );
    }

    return binary;
}

std::string converter::binaryToBase64( const Bytes& binary ) {

    if( binary.empty() ) { return std::string(); }

    static const char table64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t size   = binary.size();
    size_t steps  = size / 3;
    size_t size64 = steps * 4;
    size_t rest   = size % 3;

    std::string base64( size64 + ( rest ? 4 : 0 ), '\0' );

    for( size_t i = 0; i < steps; ++i ) {
        int a = ( ( ( binary[3 * i + 0] ) & 0b11111100 ) >> 2 );
        int b = ( ( ( binary[3 * i + 0] ) & 0b00000011 ) << 4 ) +
                ( ( ( binary[3 * i + 1] ) & 0b11110000 ) >> 4 );
        int c = ( ( ( binary[3 * i + 1] ) & 0b00001111 ) << 2 ) +
                ( ( ( binary[3 * i + 2] ) & 0b11000000 ) >> 6 );
        int d = ( ( ( binary[3 * i + 2] ) & 0b00111111 ) );
        base64[4 * i + 0] = table64[ a ];
        base64[4 * i + 1] = table64[ b ];
        base64[4 * i + 2] = table64[ c ];
        base64[4 * i + 3] = table64[ d ];
    }

    // rest
    {
        if( rest == 1 ) {
            int a = ( ( ( binary[3 * steps + 0] ) & 0b11111100 ) >> 2 );
            int b = ( ( ( binary[3 * steps + 0] ) & 0b00000011 ) << 4 );
            base64[4 * steps + 0] = table64[ a ];
            base64[4 * steps + 1] = table64[ b ];
            base64[4 * steps + 2] = '=';
            base64[4 * steps + 3] = '=';
        }

        if( rest == 2 ) {
            int a = ( ( ( binary[3 * steps + 0] ) & 0b11111100 ) >> 2 );
            int b = ( ( ( binary[3 * steps + 0] ) & 0b00000011 ) << 4 ) +
                    ( ( ( binary[3 * steps + 1] ) & 0b11110000 ) >> 4 );
            int c = ( ( ( binary[3 * steps + 1] ) & 0b00001111 ) << 2 );
            base64[4 * steps + 0] = table64[ a ];
            base64[4 * steps + 1] = table64[ b ];
            base64[4 * steps + 2] = table64[ c ];
            base64[4 * steps + 3] = '=';
        }
    }

    return base64;
}

Bytes converter::base64ToBinary( const std::string& base64 ) {
    static const std::map<char, uint8_t> table64 = {
        { 'A',  0 }, { 'B',  1 }, { 'C',  2 }, { 'D',  3 }, { 'E',  4 }, { 'F',  5 }, { 'G',  6 }, { 'H',  7 },
        { 'I',  8 }, { 'J',  9 }, { 'K', 10 }, { 'L', 11 }, { 'M', 12 }, { 'N', 13 }, { 'O', 14 }, { 'P', 15 },
        { 'Q', 16 }, { 'R', 17 }, { 'S', 18 }, { 'T', 19 }, { 'U', 20 }, { 'V', 21 }, { 'W', 22 }, { 'X', 23 },
        { 'Y', 24 }, { 'Z', 25 }, { 'a', 26 }, { 'b', 27 }, { 'c', 28 }, { 'd', 29 }, { 'e', 30 }, { 'f', 31 },
        { 'g', 32 }, { 'h', 33 }, { 'i', 34 }, { 'j', 35 }, { 'k', 36 }, { 'l', 37 }, { 'm', 38 }, { 'n', 39 },
        { 'o', 40 }, { 'p', 41 }, { 'q', 42 }, { 'r', 43 }, { 's', 44 }, { 't', 45 }, { 'u', 46 }, { 'v', 47 },
        { 'w', 48 }, { 'x', 49 }, { 'y', 50 }, { 'z', 51 }, { '0', 52 }, { '1', 53 }, { '2', 54 }, { '3', 55 },
        { '4', 56 }, { '5', 57 }, { '6', 58 }, { '7', 59 }, { '8', 60 }, { '9', 61 }, { '+', 62 }, { '/', 63 },
    };

    size_t size64 = base64.size();
    size_t steps  = size64 / 4;
    size_t size   = size64 * 3 / 4;
    Bytes binary( size );

    if( size == 0 ) { return binary; }

    size_t padding = 0;

    auto get6Bit = [&padding]( const char c ) -> uint8_t {
        if( c == '=' ) { ++padding; return 0; }

        auto it = table64.find( c );

        if( it != table64.end() ) {
            return it->second;
        }

        return 0;
    };

    for( size_t i = 0; i < steps; ++i ) {
        uint8_t a = get6Bit( base64[4 * i + 0] );
        uint8_t b = get6Bit( base64[4 * i + 1] );
        uint8_t c = get6Bit( base64[4 * i + 2] );
        uint8_t d = get6Bit( base64[4 * i + 3] );
        binary[3 * i + 0] = ( ( a & 0b111111 ) << 2 ) +
                            ( ( b & 0b110000 ) >> 4 );
        binary[3 * i + 1] = ( ( b & 0b001111 ) << 4 ) +
                            ( ( c & 0b111100 ) >> 2 );
        binary[3 * i + 2] = ( ( c & 0b000011 ) << 6 ) +
                            ( ( d & 0b111111 ) );
    }

    // remove padding
    while( padding-- ) {
        binary.pop_back();
    }

    return binary;

}

std::string converter::hexToBase64( const std::string& hex ) {
    Bytes binary = hexToBinary( hex );
    std::string base64 = binaryToBase64( binary );
    return base64;
}

std::string converter::binaryToHex( const Bytes& bytes ) {
    static const char table16[17] = "0123456789abcdef";

    std::string rv( 2 * bytes.size(), '\0' );
    size_t pos = 0;

    for( const uint8_t byte : bytes ) {
        int a = ( byte & 0b11110000 ) >> 4;
        int b = ( byte & 0b00001111 );
        rv[2 * pos + 0] = table16[a];
        rv[2 * pos + 1] = table16[b];
        ++pos;
    }

    return rv;
}
