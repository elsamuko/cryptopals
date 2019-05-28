#pragma once

#include <vector>
#include <string>

namespace utils {
uint8_t parseHex( const char& hex );
std::vector<uint8_t> hexToBinary( const std::string& hex );
std::string binaryToBase64( const std::vector<uint8_t>& binary );
std::string hexToBase64( const std::string& hex );
}
