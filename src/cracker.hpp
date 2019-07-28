#pragma once

#include "utils.hpp"
#include "crypto.hpp"

namespace cracker {

struct GuessedKey {
    uint8_t key = {0};
    float probability = {0.f};
};
//! guess single byte key, \p text has been xor'ed with
GuessedKey guessKey( const Bytes& text );

struct GuessedSize {
    size_t blockSize = {0};
    size_t suffix = {0}; // size of only prefix
    size_t prefix = {0}; // size of only suffix
};
using BlockEncryptFunc = std::function < Bytes( const Bytes& ) >;
GuessedSize guessBlockSize( const BlockEncryptFunc& encryptFunc );

std::optional<crypto::Encrypted::Type> detectECBorCBC( const Bytes& encrypted, const size_t& blockSize );

}
