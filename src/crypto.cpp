#include "crypto.hpp"

#include <memory>
#include <random>
#include <stdexcept>
#include <cstring>

#include "converter.hpp"
#include "random.hpp"
#include "hash.hpp"
#include "log.hpp"

#if 0
#include "openssl.hpp"
namespace aes = openssl;
#else
#include "aesni.hpp"
namespace aes = aesni;
#endif

Bytes crypto::XOR( const Bytes& data, const Bytes& key ) {
    size_t size1 = data.size();
    size_t size2 = key.size();
    Bytes rv( size1, 0 );

    for( size_t i = 0; i < size1; ++i ) {
        rv[i] = data[i] ^ key[i % size2];
    }

    return rv;
}

std::string crypto::XOR( const std::string& data, const std::string& key ) {
    Bytes vfirst = converter::hexToBinary( data );
    Bytes vsecond = converter::hexToBinary( key );
    Bytes vres = XOR( vfirst, vsecond );
    std::string rv = converter::binaryToHex( vres );
    return rv;
}

Bytes crypto::XOR( const Bytes& data, const uint8_t& key ) {
    size_t size = data.size();
    Bytes rv( size, 0 );

    for( size_t i = 0; i < size; ++i ) {
        rv[i] = data[i] ^ key;
    }

    return rv;
}

std::vector<Bytes> crypto::XOR( const std::vector<Bytes>& data, const Bytes& key ) {
    std::vector<Bytes> rv;
    rv.reserve( data.size() );

    for( const Bytes& one : data ) {
        rv.push_back( XOR( one, key ) );
    }

    return rv;
}

template<class Container>
Container crypto::padPKCS7( const Container& input, const size_t block ) {
    size_t size = input.size();

    size_t padSize = block - size % block;
    Container rv = input;
    rv.reserve( size + padSize );

    for( uint8_t i = 0; i < padSize; ++i ) {
        rv.push_back( static_cast<typename Container::value_type>( padSize ) );
    }

    return rv;
}

template Bytes crypto::padPKCS7( const Bytes& input, const size_t blockSize );
template std::string crypto::padPKCS7( const std::string& input, const size_t blockSize );

template<class Container>
Container crypto::unpadPKCS7( const Container& input ) {
    using type = typename Container::value_type;

    if( input.empty() ) { return {}; }

    size_t size = input.size();
    type padSize = input.back();

    if( input.size() < static_cast<size_t>( padSize ) ) {
        throw std::invalid_argument( "PKCS7: Padding too big" );
    }

    if( padSize == 0 ) {
        throw std::invalid_argument( "PKCS7: Padding cannot be zero" );
    }

    // validate PKCS7 format
    for( type i = 1; i <= padSize; ++i ) {

        if( input[size - i] != padSize ) {
            throw std::invalid_argument( "PKCS7: Bad padding" );
        }
    }

    return Container( input.cbegin(), input.cend() - static_cast<typename Container::difference_type>( padSize ) );
}

template Bytes crypto::unpadPKCS7( const Bytes& input );
template std::string crypto::unpadPKCS7( const std::string& input );

Bytes crypto::encryptAES128ECB( const Bytes& text, const Bytes& key ) {

    if( key.size() != crypto::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << crypto::blockSize );
        return {};
    }

    Bytes padded = padPKCS7( text );
    Bytes cipher( padded.size(), 0 );

    int len = aes::encryptAES128ECB( padded.data(), cipher.data(), padded.size(), key.data() );

    cipher.resize( static_cast<size_t>( len ) );
    return cipher;
}

Bytes crypto::decryptAES128ECB( const Bytes& data, const Bytes& key ) {

    if( key.size() != crypto::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << crypto::blockSize );
        return {};
    }

    if( data.size() % crypto::blockSize != 0 ) {
        LOG( "Error: Invalid data size " << data.size() << " % " << crypto::blockSize << " != 0" );
        return {};
    }

    Bytes plain( data.size(), 0 );

    int len = aes::decryptAES128ECB( data.data(), plain.data(), data.size(), key.data() );

    plain.resize( static_cast<size_t>( len ) );
    plain = unpadPKCS7( plain );

    return plain;
}

Bytes crypto::encryptAES128CBC( const Bytes& text, const Bytes& key, const Bytes& iv ) {

    if( key.size() != crypto::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << crypto::blockSize );
        return {};
    }

    if( iv.size() != crypto::blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << crypto::blockSize );
        return {};
    }

    Bytes padded = crypto::padPKCS7( text );
    size_t steps = padded.size() / crypto::blockSize;

    Bytes encrypted = iv;
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes plain = crypto::XOR( encrypted,
                                   Bytes( padded.cbegin() + ( i + 0 ) * crypto::blockSize,
                                          padded.cbegin() + ( i + 1 ) * crypto::blockSize ) );
        aes::encryptAES128ECB( plain.data(), encrypted.data(), plain.size(), key.data() );
        result = result + encrypted;
    }

    return result;
}


Bytes crypto::decryptAES128CBC( const Bytes& data, const Bytes& key, const Bytes& iv ) {

    if( key.size() != crypto::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << crypto::blockSize );
        return {};
    }

    if( iv.size() != crypto::blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << crypto::blockSize );
        return {};
    }

    if( data.size() % crypto::blockSize != 0 ) {
        LOG( "Error: Invalid data size " << data.size() << " % " << crypto::blockSize << " != 0" );
        return {};
    }

    size_t steps = data.size() / crypto::blockSize;

    Bytes newIV = iv;
    Bytes decrypted( crypto::blockSize, 0 );
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes encrypted = Bytes( data.cbegin() + ( i + 0 ) * crypto::blockSize,
                                 data.cbegin() + ( i + 1 ) * crypto::blockSize );
        aes::decryptAES128ECB( encrypted.data(), decrypted.data(), encrypted.size(), key.data() );
        Bytes plain = crypto::XOR( newIV, decrypted );
        result.insert( result.end(), plain.cbegin(), plain.cend() );
        newIV = encrypted;
    }

    result = unpadPKCS7( result );

    return result;
}


Bytes crypto::genKey() {
    return randombuffer::get( crypto::blockSize );
}

size_t crypto::randSize( const size_t& from, const size_t& to ) {
    std::random_device rd;
    std::mt19937 gen( rd() );
    std::uniform_int_distribution<size_t> distribution( from, to );
    size_t rv = distribution( gen );
    return rv ;
}

bool crypto::flipCoin() {
    bool rv = bool( randSize( 0, 1 ) );
    return rv ;
}

crypto::Encrypted crypto::encryptECBOrCBC( const Bytes& data ) {

    // prepend and append random data of random size
    Bytes prefix  = randombuffer::get( randSize( 5, 10 ) );
    Bytes suffix = randombuffer::get( randSize( 5, 10 ) );
    Bytes all = prefix + data + suffix;

    // random key and iv
    Bytes key = genKey();
    Bytes iv = genKey();

    if( flipCoin() ) {
        return { Encrypted::Type::CBC, encryptAES128CBC( all, key, iv ) };
    } else {
        return { Encrypted::Type::ECB, encryptAES128ECB( all, key ) };
    }
}

Bytes crypto::encryptECBWithSecretSuffix( const Bytes& data ) {
    // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
    Bytes key = { 0x61, 0x82, 0xd5, 0x3a, 0x29, 0x82, 0xcb, 0x4f, 0x2d, 0x9e, 0x04, 0x3b, 0xe5, 0xdf, 0x97, 0xb3 };

    std::string base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                         "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                         "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                         "YnkK";

    Bytes suffix = converter::base64ToBinary( base64 );
    Bytes all = data + suffix;

    return encryptAES128ECB( all, key );
}

std::ostream& crypto::operator<<( std::ostream& os, const crypto::Encrypted::Type& type ) {
    switch( type ) {
        case crypto::Encrypted::Type::CBC:
            os << "CBC";
            break;

        case crypto::Encrypted::Type::ECB:
            os << "EBC";
            break;
    }

    return os;
}

Bytes crypto::encryptECBWithRandomPrefixAndSecretSuffix( const Bytes& data ) {
    // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
    Bytes key = { 0x3e, 0xb0, 0x62, 0x32, 0x19, 0x3e, 0x12, 0x61, 0xc5, 0x84, 0x45, 0x15, 0x2c, 0x1d, 0x47, 0xb0 };

    static Bytes prefix  = randombuffer::get( randSize( 0, 50 ) );

    std::string base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                         "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                         "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                         "YnkK";

    Bytes suffix = converter::base64ToBinary( base64 );

    Bytes all = prefix + data + suffix;

    return encryptAES128ECB( all, key );
}

Bytes helperAES128CTR( const Bytes& text, const Bytes& key, const uint64_t& nonce ) {
    Bytes padded = crypto::padPKCS7( text );
    Bytes encrypted;
    encrypted.reserve( padded.size() );

    uint64_t counter = 0;
    Bytes nonce_counter( crypto::blockSize );
    static_assert( crypto::blockSize == 2 * sizeof( nonce ), "nonce does not fit first half of AES block!" );
    static_assert( crypto::blockSize == 2 * sizeof( counter ), "counter does not fit second half of AES block!" );
    std::memcpy( &nonce_counter[0], &nonce, sizeof( nonce ) );

    for( size_t i = 0; i < padded.size(); i += crypto::blockSize ) {
        Bytes sub( padded.cbegin() + i, padded.cbegin() + i + crypto::blockSize );
        std::memcpy( &nonce_counter[crypto::blockSize / 2], &counter, sizeof( counter ) );
        Bytes xorStream = crypto::encryptAES128ECB( nonce_counter, key );
        Bytes scrambled = crypto::XOR( sub, xorStream );
        encrypted.insert( encrypted.cend(), scrambled.cbegin(), scrambled.cend() );
        counter++;
    }

    encrypted.resize( text.size() );

    return encrypted;
}

Bytes crypto::editAES128CTR( const Bytes& encrypted, const size_t& offset, const Bytes& replacement, const Bytes& key, const uint64_t& nonce ) {

    if( ( offset + replacement.size() ) > encrypted.size() ) {
        LOG( "Replacement doesn't fit into encrypted stream" );
        return Bytes();
    }

    Bytes nonce_counter( crypto::blockSize );
    Bytes padded = crypto::padPKCS7( encrypted );

    // |                |                |                |                |
    // |                |<----######################----->|                |
    size_t from = offset - offset % crypto::blockSize;
    size_t to   = offset + replacement.size() - ( offset + replacement.size() ) % crypto::blockSize + crypto::blockSize;

    // decrypt part where replacement should go
    {
        uint64_t counter = from / crypto::blockSize;
        std::memcpy( &nonce_counter[0], &nonce, sizeof( nonce ) );

        for( size_t i = from; i < to; i += crypto::blockSize ) {
            Bytes sub( padded.cbegin() + i, padded.cbegin() + i + crypto::blockSize );
            std::memcpy( &nonce_counter[crypto::blockSize / 2], &counter, sizeof( counter ) );
            Bytes xorStream = crypto::encryptAES128ECB( nonce_counter, key );
            Bytes unscrambled = crypto::XOR( sub, xorStream );
            std::memcpy( &padded[i], unscrambled.data(), crypto::blockSize );
            counter++;
        }
    }

    // replace clear text
    std::memcpy( &padded[offset], replacement.data(), replacement.size() );

    // re-encrypt
    {
        uint64_t counter = from / crypto::blockSize;
        std::memcpy( &nonce_counter[0], &nonce, sizeof( nonce ) );

        for( size_t i = from; i < to; i += crypto::blockSize ) {
            Bytes sub( padded.cbegin() + i, padded.cbegin() + i + crypto::blockSize );
            std::memcpy( &nonce_counter[crypto::blockSize / 2], &counter, sizeof( counter ) );
            Bytes xorStream = crypto::encryptAES128ECB( nonce_counter, key );
            Bytes scrambled = crypto::XOR( sub, xorStream );
            std::memcpy( &padded[i], scrambled.data(), crypto::blockSize );
            counter++;
        }
    }

    padded.resize( encrypted.size() );
    return padded;
}

Bytes crypto::encryptAES128CTR( const Bytes& text, const Bytes& key, const uint64_t& nonce ) {
    return helperAES128CTR( text, key, nonce );
}

Bytes crypto::decryptAES128CTR( const Bytes& text, const Bytes& key, const uint64_t& nonce ) {
    return helperAES128CTR( text, key, nonce );
}

Bytes helperMersenneCTR( const Bytes& text, const uint16_t& key ) {
    const size_t blockSize = sizeof( uint32_t );
    Bytes padded = crypto::padPKCS7( text, blockSize );
    Bytes encrypted;
    encrypted.reserve( padded.size() );

    Mersenne mersenne( key );

    for( size_t i = 0; i < padded.size(); i += blockSize ) {
        Bytes sub( padded.cbegin() + i, padded.cbegin() + i + blockSize );
        uint32_t r = mersenne.get();
        Bytes stream( blockSize );
        memcpy( stream.data(), &r, blockSize );
        Bytes scrambled = crypto::XOR( sub, stream );
        encrypted.insert( encrypted.cend(), scrambled.cbegin(), scrambled.cend() );
    }

    encrypted.resize( text.size() );

    return encrypted;
}

Bytes crypto::encryptMersenneCTR( const Bytes& text, const uint16_t& key ) {
    return helperMersenneCTR( text, key );
}

Bytes crypto::decryptMersenneCTR( const Bytes& text, const uint16_t& key ) {
    return helperMersenneCTR( text, key );
}

Bytes crypto::macSha1( const Bytes& text, const Bytes& key ) {
    return hash::sha1( key + text );
}

Bytes crypto::macMd4( const Bytes& text, const Bytes& key ) {
    return hash::md4( key + text );
}

Bytes crypto::hmacSha1( const Bytes& text, Bytes key ) {
    size_t sha1BlockSize = 64;

    if( key.size() > sha1BlockSize ) {
        key = hash::sha1( key );
    }

    if( key.size() < sha1BlockSize ) {
        key.resize( sha1BlockSize, 0 );
    }

    Bytes o_key_pad = crypto::XOR( key, Bytes( sha1BlockSize, 0x5c ) );
    Bytes i_key_pad = crypto::XOR( key, Bytes( sha1BlockSize, 0x36 ) );

    Bytes hmac = hash::sha1( o_key_pad + hash::sha1( i_key_pad + text ) );
    return hmac;
}
