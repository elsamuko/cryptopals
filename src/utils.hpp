#pragma once

#include <functional>
#include <optional>
#include <map>

#include "types.hpp"

#define CHECK( A ) if( !(A) ) { LOG( "[FAILURE] : "#A ); } \
                         else { LOG_DEBUG( "[SUCCESS] : "#A ); }
#define CHECK_EQ( A, B ) if( (A) != (B) ) { LOG( "[FAILURE] : "#A" == "#B", " << A << " != " << B ); } \
                                     else { LOG_DEBUG( "[SUCCESS] : "#A" == "#B ); }
#define CHECK_NE( A, B ) if( (A) == (B) ) { LOG( "[FAILURE] : "#A" != "#B", " << A << " == " << B ); } \
                                     else { LOG_DEBUG( "[SUCCESS] : "#A" != "#B ); }

#define CHECK_THROW( A ) try{ A; LOG( "[FAILURE] : Throws not: "#A ); } \
                        catch(...) { LOG_DEBUG( "[SUCCESS] : Throws: "#A ); }

namespace utils {

//! split \p mono into \p parts parts
std::vector<Bytes> disperse( const Bytes& mono, const size_t& parts );

//! analyze, if \p text is an english text
//! higher is better
float isEnglishText( const Bytes& text );

//! analyze, if \p text are english sentences
//! higher is better
float areEnglishSentences( const std::vector<Bytes>& sentences );

//! reads \p filename with newline separated hex lines
std::vector<Bytes> fromHexFile( const std::string& filename );

//! reads \p filename with newline separated lines
std::vector<std::string> linesFromFile( const std::string& filename );

//! writes \p data to \p filename
void toFile( const std::string& filename, const Bytes& data );

//! reads data from \p filename
Bytes fromFile( const std::string& filename );

//! reads \p filename with base64 content
Bytes fromBase64File( const std::string& filename );

//! \returns the sum of bitwise differences of two arrays
template<class Container>
size_t hammingDistance( const Container& first, const Container& second );

//! \returns the shannon entropy of data
//! \sa https://rosettacode.org/wiki/Entropy#C.2B.2B
float shannonEntropy( const Bytes& data );

//! \param params from a GET request, e.g. foo=bar&baz=qux&zap=zazzle
//! \returns map with parsed params, e.g. { foo: 'bar', baz: 'qux', zap: 'zazzle' }
std::map<std::string, std::string> parseGETParams( const std::string& params );

//! \returns true, if string contains semicolon separated pair admin=true
bool isAdmin( const std::string& params );

//! \returns false, if string contains control characters
bool isAscii( const std::string& params );

//! \returns "email=foo@bar.com&uid=10&role=user" for input "foo@bar.com"
std::string profileFor( const std::string& mail );

//! \returns "comment1=cooking%20MCs;userdata=HASE;comment2=%20like%20a%20pound%20of%20bacon" for input "HASE"
std::string generateGETRequest( const std::string& userdata );

//! splits string into 16 bytes and logs them
void logBlock( const std::string& in );

//! \returns printf style string
template <typename ... Args>
std::string format( const char* format, Args const& ... args ) {

    size_t size = snprintf( nullptr, 0, format, args... );
    std::string text( size, '\0' );
    snprintf( text.data(), text.size() + 1, format, args... );

    return text;
}

}

Bytes operator+( const Bytes& first, const Bytes& second );
std::ostream& operator<<( std::ostream& os, const Bytes& bytes );
template<class A, class B>
std::ostream& operator<<( std::ostream& os, const std::map<A, B>& map );
