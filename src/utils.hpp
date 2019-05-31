#pragma once

#include <vector>
#include <string>

#include "log.hpp"

#define CHECK( A ) if( !(A) ) { LOG( "Failed check for "#A ); }
#define CHECK_EQ( A, B ) if( (A) != (B) ) { LOG( "Failed check for "#A" == "#B", " << A << " != " << B ); }

namespace utils {
uint8_t parseHex( const char& hex );
std::vector<uint8_t> hexToBinary( const std::string& hex );
std::string binaryToHex( const std::vector<uint8_t>& bytes );

std::string binaryToBase64( const std::vector<uint8_t>& binary );
std::string hexToBase64( const std::string& hex );

std::string XOR( const std::string& first, const std::string& second );
std::vector<uint8_t> XOR( const std::vector<uint8_t>& first, const std::vector<uint8_t>& second );
}
