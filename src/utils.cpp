#include "utils.hpp"

#include <map>
#include <cmath>
#include <fstream>

uint8_t utils::parseHex( const char& hex ) {
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

Bytes utils::hexToBinary( const std::string& hex ) {
    size_t size   = hex.size() / 2;
    Bytes binary( size, 0 );

    for( size_t i = 0; i < size; ++i ) {
        uint8_t higher = static_cast<uint8_t>( parseHex( hex[2 * i + 0] ) );
        uint8_t lower  = static_cast<uint8_t>( parseHex( hex[2 * i + 1] ) );
        binary[i] =  lower + 16 * higher;
    }

    return binary;
}

std::string utils::binaryToBase64( const Bytes& binary ) {

    static const char table64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t size   = binary.size();
    size_t steps  = size / 3;
    size_t size64 = size * 4 / 3;
    size_t rest   = size % 3;

    std::string base64( size64 + 4 * rest, '\0' );

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

std::string utils::hexToBase64( const std::string& hex ) {
    Bytes binary = hexToBinary( hex );
    std::string base64 = binaryToBase64( binary );
    return base64;
}

Bytes utils::XOR( const Bytes& first, const Bytes& second ) {
    size_t size = first.size();
    Bytes rv( size, 0 );

    if( first.size() != second.size() ) {
        LOG( "Error: input sizes are not equal!" );
        return rv;
    }

    for( size_t i = 0; i < size; ++i ) {
        rv[i] = first[i] xor second[i];
    }

    return rv;
}

std::string utils::binaryToHex( const Bytes& bytes ) {
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

std::string utils::XOR( const std::string& first, const std::string& second ) {
    Bytes vfirst = hexToBinary( first );
    Bytes vsecond = hexToBinary( second );
    Bytes vres = XOR( vfirst, vsecond );
    std::string rv = binaryToHex( vres );
    return rv;
}

// higher is better
float utils::isEnglishText( const Bytes& text ) {
    std::map<int, float> freqs;

    for( const uint8_t c : text ) {
        if( std::isalpha( c ) ) {
            if( std::isupper( c ) ) {
                freqs[std::tolower( c )] += 1;
            } else {
                freqs[std::tolower( c )] += 2;
            }
        }
    }

    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    float prob_ = freqs[' '];
    float probE = freqs['e'];
    float probT = freqs['t'];
    float probA = freqs['a'];
    float probO = freqs['o'];
    float probI = freqs['i'];
    float probN = freqs['n'];
    float probS = freqs['s'];

    return prob_ + probE + probT + probA + probO + probI + probN + probS;
}

Bytes utils::XOR( const Bytes& first, const uint8_t& key ) {
    size_t size = first.size();
    Bytes rv( size, 0 );

    for( size_t i = 0; i < size; ++i ) {
        rv[i] = first[i] xor key;
    }

    return rv;
}

std::vector<Bytes> utils::fromHexFile( const std::string& filename ) {
    std::vector<Bytes> rv;
    std::ifstream file( filename.c_str(), std::ios::binary | std::ios::in );

    if( !file ) { return rv; }

    std::string line;
    rv.reserve( 32 );

    while( std::getline( file, line ) ) {
        rv.emplace_back( hexToBinary( line ) );
    }

    return rv;
}

utils::Guess utils::guessKey( const Bytes& text ) {
    float best = 0.f;
    uint8_t bestKey = 0;

    for( uint8_t key = 0; key != 255; ++key ) {
        Bytes decrypted = utils::XOR( text, key );
        float prob = utils::isEnglishText( decrypted );

        if( prob > best ) {
            best = prob;
            bestKey = key;
        }
    }

    return {bestKey, best};
}
