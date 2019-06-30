#pragma once

#include "utils.hpp"
#include "crypto.hpp"

namespace cracker {

struct Guess {
    uint8_t key;
    float probability;
};
//! guess single byte key, \p text has been xor'ed with
Guess guessKey( const Bytes& text );

using BlockEncryptFunc = std::function < Bytes( const Bytes& ) >;
size_t guessBlockSize( const BlockEncryptFunc& encryptFunc );

std::optional<crypto::Encrypted::Type> detectECBorCBC( const Bytes& encrypted );

}
