#pragma once

#include "types.hpp"

#define CHECK( A ) if( !(A) ) { LOG( "Failed check for "#A ); }
#define CHECK_EQ( A, B ) if( (A) != (B) ) { LOG( "[FAILURE] : "#A" == "#B", " << A << " != " << B ); } \
                                     else { LOG( "[SUCCESS] : "#A" == "#B ); }

namespace utils {

//! split \p mono into \p parts parts
std::vector<Bytes> disperse( const Bytes& mono, const size_t& parts );

struct Guess {
    uint8_t key;
    float probability;
};
//! guess single byte key, \p text has been xor'ed with
Guess guessKey( const Bytes& text );

//! analyze, if \p text is an english text
//! higher is better
float isEnglishText( const Bytes& text );

//! reads \p filename with newline separated hex lines
std::vector<Bytes> fromHexFile( const std::string& filename );

//! reads \p filename with newline separated lines
std::vector<std::string> fromFile( const std::string& filename );

//! writes \p data to \p filename
void toFile( const std::string& filename, const Bytes& data );

//! reads \p filename with base64 content
Bytes fromBase64File( const std::string& filename );

//! \returns the sum of bitwise differences of two arrays
template<class Container>
size_t hammingDistance( const Container& first, const Container& second );

//! \returns the shannon entropy of data
//! \sa https://rosettacode.org/wiki/Entropy#C.2B.2B
float shannonEntropy( const Bytes& data );

}

Bytes operator+( const Bytes& first, const Bytes& second );
std::ostream& operator<<( std::ostream& os, const Bytes& bytes );
