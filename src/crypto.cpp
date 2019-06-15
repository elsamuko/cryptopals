#include "crypto.hpp"

#include <memory>

#include "openssl/evp.h"

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

const size_t blockSize = ( size_t )EVP_CIPHER_block_size( EVP_aes_128_ecb() );

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

Bytes crypto::encryptAES128ECB( const Bytes& text, const Bytes& key ) {

    size_t blockSize = ( size_t )EVP_CIPHER_block_size( EVP_aes_128_ecb() );

    if( key.size() != blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << blockSize );
        return {};
    }

    unsigned char* c_iv = nullptr;
    unsigned char* c_key = const_cast<unsigned char*>( key.data() );

    unsigned char* c_plaintext = ( unsigned char* )( text.data() );;
    int plaintext_len = text.size();

    Bytes cipher( plaintext_len + key.size(), 0 );
    unsigned char* c_ciphertext = reinterpret_cast<unsigned char*>( cipher.data() );

    int len = openssl::encrypt( c_plaintext, plaintext_len, c_key, c_iv, c_ciphertext );

    cipher.resize( ( size_t )len );
    return cipher;
}

Bytes crypto::decryptAES128ECB( const Bytes& data, const Bytes& key ) {

    size_t blockSize = ( size_t )EVP_CIPHER_block_size( EVP_aes_128_ecb() );

    if( key.size() != blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << blockSize );
        return {};
    }

    unsigned char* c_iv = nullptr;
    unsigned char* c_key = const_cast<unsigned char*>( key.data() );

    unsigned char* c_ciphertext = const_cast<unsigned char*>( data.data() );;
    int ciphertext_len = data.size();

    Bytes plain( ciphertext_len, 0 );
    unsigned char* c_plaintext = reinterpret_cast<unsigned char*>( plain.data() );

    int len = openssl::decrypt( c_ciphertext, ciphertext_len, c_key, c_iv, c_plaintext );

    plain.resize( ( size_t )len );
    return plain;
}

template<class Container>
Container crypto::padPKCS7( const Container& input, const uint8_t blockSize ) {
    size_t size = input.size();

    uint8_t padSize = blockSize - size % blockSize;
    Container rv = input;
    rv.reserve( size + padSize );

    for( uint8_t i = 0; i < padSize; ++i ) {
        rv.push_back( padSize );
    }

    return rv;
}

template Bytes crypto::padPKCS7( const Bytes& input, const uint8_t blockSize );
template std::string crypto::padPKCS7( const std::string& input, const uint8_t blockSize );

template<class Container>
Container crypto::unpadPKCS7( const Container& input ) {
    if( input.empty() ) { return {}; }

    size_t padSize = input.back();

    if( input.size() < padSize ) { return {}; }

    return Container( input.cbegin(), input.cend() - padSize );
}

template Bytes crypto::unpadPKCS7( const Bytes& input );
template std::string crypto::unpadPKCS7( const std::string& input );

Bytes crypto::encryptAES128CBC( const Bytes& text, const Bytes& key, const Bytes& iv ) {

    size_t blockSize = ( size_t )EVP_CIPHER_block_size( EVP_aes_128_ecb() );

    if( key.size() != blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << blockSize );
        return {};
    }

    if( iv.size() != blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << blockSize );
        return {};
    }

    Bytes padded = text;

    if( text.size() % blockSize > 0 ) {
        padded = crypto::padPKCS7( text, blockSize );
    }

    size_t steps = padded.size() / blockSize;

    Bytes encrypted = iv;
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes plain = crypto::XOR( encrypted,
                                   Bytes( padded.cbegin() + ( i + 0 ) * blockSize,
                                          padded.cbegin() + ( i + 1 ) * blockSize ) );
        openssl::encrypt( plain.data(), plain.size(), key.data(), nullptr, encrypted.data() );
        result.insert( result.end(), encrypted.cbegin(), encrypted.cend() );
    }

    return result;
}


Bytes crypto::decryptAES128CBC( const Bytes& data, const Bytes& key, const Bytes& iv ) {
    size_t blockSize = ( size_t )EVP_CIPHER_block_size( EVP_aes_128_ecb() );

    if( key.size() != blockSize ) {
        LOG( "Error: Invalid key size " << key.size() << " != " << blockSize );
        return {};
    }

    if( iv.size() != blockSize ) {
        LOG( "Error: Invalid iv size " << iv.size() << " != " << blockSize );
        return {};
    }

    if( data.size() % blockSize != 0 ) {
        LOG( "Error: Invalid data size " << data.size() << " % " << blockSize << " != 0" );
        return {};
    }

    size_t steps = data.size() / blockSize;

    Bytes newIV = iv;
    Bytes decrypted( blockSize, 0 );
    Bytes result;

    for( size_t i = 0; i < steps; ++i ) {
        Bytes encrypted = Bytes( data.cbegin() + ( i + 0 ) * blockSize,
                                 data.cbegin() + ( i + 1 ) * blockSize );
        openssl::decrypt( encrypted.data(), encrypted.size(), key.data(), nullptr, decrypted.data() );
        Bytes plain = crypto::XOR( newIV, decrypted );
        result.insert( result.end(), plain.cbegin(), plain.cend() );
        newIV = encrypted;
    }

    return result;
}
