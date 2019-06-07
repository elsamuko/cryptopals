#pragma once

#include "utils.hpp"

namespace crypto {
std::string XOR( const std::string& first, const std::string& second );
Bytes XOR( const Bytes& first, const Bytes& second );
Bytes XOR( const Bytes& first, const uint8_t& key );

std::string decryptAES128ECB( const Bytes& data, const Bytes& key );
}
