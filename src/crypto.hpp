#pragma once

#include "utils.hpp"

namespace crypto {
std::string XOR( const std::string& first, const std::string& second );
Bytes XOR( const Bytes& first, const Bytes& second );
Bytes XOR( const Bytes& first, const uint8_t& key );

Bytes       encryptAES128ECB( const std::string& text, const Bytes& key );
std::string decryptAES128ECB( const Bytes& data, const Bytes& key );

//! pad \p input in PKCS#7 to \p size bytes
template <class Container>
Container padPKCS7( const Container& input, const uint8_t blockSize );

}
