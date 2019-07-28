#include "crypto.hpp"

#include <memory>
#include <random>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "converter.hpp"
#include "log.hpp"

#define BREAK_IF( COND, MSG ) if( ( COND ) ) { LOG( MSG ); break; }

Bytes crypto::XOR( const Bytes& first, const Bytes& second ) {
    size_t size1 = first.size();
    size_t size2 = second.size();
    Bytes rv( size1, 0 );

    for( size_t i = 0; i < size1; ++i ) {
        rv[i] = first[i] ^ second[i % size2];
    }

    return rv;
}

std::string crypto::XOR( const std::string& first, const std::string& second ) {
    Bytes vfirst = converter::hexToBinary( first );
    Bytes vsecond = converter::hexToBinary( second );
    Bytes vres = XOR( vfirst, vsecond );
    std::string rv = converter::binaryToHex( vres );
    return rv;
}

Bytes crypto::XOR( const Bytes& first, const uint8_t& key ) {
    size_t size = first.size();
    Bytes rv( size, 0 );

    for( size_t i = 0; i < size; ++i ) {
        rv[i] = first[i] ^ key;
    }

    return rv;
}

namespace openssl {

const size_t blockSize = static_cast<size_t>( EVP_CIPHER_block_size( EVP_aes_128_ecb() ) );

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
int encrypt( const unsigned char* plaintext, const int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext ) {

    int ciphertext_len = 0;

    do {
        int len = 0;

        std::shared_ptr<EVP_CIPHER_CTX> ctx( EVP_CIPHER_CTX_new(), []( EVP_CIPHER_CTX * ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        } );
        BREAK_IF( !ctx, "Error: Invalid ctx" );

        int rv = EVP_EncryptInit_ex( ctx.get(), EVP_aes_128_ecb(), nullptr, key, iv );
        BREAK_IF( rv != 1, "Error: EVP_EncryptInit_ex returned " << rv );

        rv = EVP_CIPHER_CTX_set_padding( ctx.get(), 0 );
        BREAK_IF( rv != 1, "Error: EVP_CIPHER_CTX_set_padding returned " << rv );

        rv = EVP_EncryptUpdate( ctx.get(), ciphertext, &len, plaintext, plaintext_len );
        BREAK_IF( rv != 1, "Error: EVP_EncryptUpdate returned " << rv );

        ciphertext_len = len;

        rv = EVP_EncryptFinal_ex( ctx.get(), ciphertext + len, &len );
        BREAK_IF( rv != 1, "Error: EVP_EncryptFinal_ex returned " << rv );

        ciphertext_len += len;

    } while( false );

    return ciphertext_len;
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message
int decrypt( const unsigned char* ciphertext, const int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext ) {

    int plaintext_len = 0;

    do {
        int len = 0;

        std::shared_ptr<EVP_CIPHER_CTX> ctx( EVP_CIPHER_CTX_new(), []( EVP_CIPHER_CTX * ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        } );
        BREAK_IF( !ctx, "Error: Invalid ctx" );

        int rv = EVP_DecryptInit_ex( ctx.get(), EVP_aes_128_ecb(), nullptr, key, iv );
        BREAK_IF( rv != 1, "Error: EVP_DecryptInit_ex returned " << rv );

        rv = EVP_CIPHER_CTX_set_padding( ctx.get(), 0 );
        BREAK_IF( rv != 1, "Error: EVP_CIPHER_CTX_set_padding returned " << rv );

        rv = EVP_DecryptUpdate( ctx.get(), plaintext, &len, ciphertext, ciphertext_len );
        BREAK_IF( rv != 1, "Error: EVP_DecryptUpdate returned " << rv );

        plaintext_len = len;

        rv = EVP_DecryptFinal_ex( ctx.get(), plaintext + len, &len );
        BREAK_IF( rv != 1, "Error: EVP_DecryptFinal_ex returned " << rv );

        plaintext_len += len;

    } while( false );

    return plaintext_len;
}

}

template<class Container>
Container crypto::padPKCS7( const Container& input, const size_t blockSize ) {
    size_t size = input.size();

    size_t padSize = blockSize - size % blockSize;
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
    if( input.empty() ) { return {}; }

    size_t padSize = static_cast<size_t>( input.back() );

    if( input.size() < padSize ) { return {}; }

    return Container( input.cbegin(), input.cend() - static_cast<typename Container::difference_type>( padSize ) );
}

template Bytes crypto::unpadPKCS7( const Bytes& input );
template std::string crypto::unpadPKCS7( const std::string& input );


Bytes crypto::encryptAES128ECB( const Bytes& text, const Bytes& key ) {

    if( key.size() != openssl::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << openssl::blockSize );
        return {};
    }

    Bytes padded = padPKCS7( text, openssl::blockSize );
    Bytes cipher( padded.size(), 0 );

    int len = openssl::encrypt( padded.data(), static_cast<int>( padded.size() ), key.data(), nullptr, cipher.data() );

    cipher.resize( static_cast<size_t>( len ) );
    return cipher;
}

Bytes crypto::decryptAES128ECB( const Bytes& data, const Bytes& key ) {

    if( key.size() != openssl::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << openssl::blockSize );
        return {};
    }

    if( data.size() % openssl::blockSize != 0 ) {
        LOG( "Error: Invalid data size " << data.size() << " % " << openssl::blockSize << " != 0" );
        return {};
    }

    Bytes plain( data.size(), 0 );

    int len = openssl::decrypt( data.data(), static_cast<int>( data.size() ), key.data(), nullptr, plain.data() );

    plain.resize( static_cast<size_t>( len ) );
    plain = unpadPKCS7( plain );

    return plain;
}

Bytes crypto::encryptAES128CBC( const Bytes& text, const Bytes& key, const Bytes& iv ) {

    if( key.size() != openssl::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << openssl::blockSize );
        return {};
    }

    if( iv.size() != openssl::blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << openssl::blockSize );
        return {};
    }

    Bytes padded = crypto::padPKCS7( text, openssl::blockSize );
    size_t steps = padded.size() / openssl::blockSize;

    Bytes encrypted = iv;
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes plain = crypto::XOR( encrypted,
                                   Bytes( padded.cbegin() + ( i + 0 ) * openssl::blockSize,
                                          padded.cbegin() + ( i + 1 ) * openssl::blockSize ) );
        openssl::encrypt( plain.data(), plain.size(), key.data(), nullptr, encrypted.data() );
        result = result + encrypted;
    }

    return result;
}


Bytes crypto::decryptAES128CBC( const Bytes& data, const Bytes& key, const Bytes& iv ) {

    if( key.size() != openssl::blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << openssl::blockSize );
        return {};
    }

    if( iv.size() != openssl::blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << openssl::blockSize );
        return {};
    }

    if( data.size() % openssl::blockSize != 0 ) {
        LOG( "Error: Invalid data size " << data.size() << " % " << openssl::blockSize << " != 0" );
        return {};
    }

    size_t steps = data.size() / openssl::blockSize;

    Bytes newIV = iv;
    Bytes decrypted( openssl::blockSize, 0 );
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes encrypted = Bytes( data.cbegin() + ( i + 0 ) * openssl::blockSize,
                                 data.cbegin() + ( i + 1 ) * openssl::blockSize );
        openssl::decrypt( encrypted.data(), encrypted.size(), key.data(), nullptr, decrypted.data() );
        Bytes plain = crypto::XOR( newIV, decrypted );
        result.insert( result.end(), plain.cbegin(), plain.cend() );
        newIV = encrypted;
    }

    result = unpadPKCS7( result );

    return result;
}

Bytes crypto::randBytes( const size_t& size ) {
    // uninitialized buffer
    Bytes buffer( size );

    int rv = RAND_bytes( buffer.data(), buffer.size() );

    if( rv != 1 ) {
        LOG( "Error: RAND_bytes returned " << rv );
        return {};
    }

    return buffer;
}

Bytes crypto::genKey() {
    return randBytes( openssl::blockSize );
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
    Bytes prefix  = randBytes( randSize( 5, 10 ) );
    Bytes suffix = randBytes( randSize( 5, 10 ) );
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

    static Bytes prefix  = randBytes( randSize( 0, 50 ) );

    std::string base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                         "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                         "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                         "YnkK";

    Bytes suffix = converter::base64ToBinary( base64 );

    Bytes all = prefix + data + suffix;

    return encryptAES128ECB( all, key );
}
