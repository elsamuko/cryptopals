#pragma once

#include "types.hpp"

namespace converter {
Bytes hexToBinary( const std::string& hex );
std::string binaryToHex( const Bytes& bytes );

std::string binaryToBase64( const Bytes& binary );
Bytes base64ToBinary( const std::string& base64 );
std::string hexToBase64( const std::string& hex );
}
