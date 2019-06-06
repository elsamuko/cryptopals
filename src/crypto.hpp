#pragma once

#include "utils.hpp"

namespace crypto {
std::string decryptAES128ECB( const Bytes& data, const Bytes& key );
}
