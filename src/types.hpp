#pragma once

#include <vector>
#include <string>

using Bytes = std::vector<uint8_t>;
using Byte = uint8_t;

inline std::string str( const Bytes& bytes ) {
    return std::string( bytes.cbegin(), bytes.cend() );
}

inline Bytes bytes( const std::string& string ) {
    return Bytes( string.cbegin(), string.cend() );
}
