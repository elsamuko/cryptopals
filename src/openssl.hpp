#pragma once

#include <memory>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "log.hpp"

#define BREAK_IF( COND, MSG ) if( ( COND ) ) { LOG( MSG ); break; }

namespace openssl {

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
inline size_t encryptAES128ECB( const uint8_t* plaintext, uint8_t* ciphertext, const size_t length, const uint8_t* userkey ) {

    size_t ciphertext_len = 0;

    do {
        int len = 0;

        std::shared_ptr<EVP_CIPHER_CTX> ctx( EVP_CIPHER_CTX_new(), []( EVP_CIPHER_CTX * ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        } );
        BREAK_IF( !ctx, "Error: Invalid ctx" );

        int rv = EVP_EncryptInit_ex( ctx.get(), EVP_aes_128_ecb(), nullptr, userkey, nullptr );
        BREAK_IF( rv != 1, "Error: EVP_EncryptInit_ex returned " << rv );

        rv = EVP_CIPHER_CTX_set_padding( ctx.get(), 0 );
        BREAK_IF( rv != 1, "Error: EVP_CIPHER_CTX_set_padding returned " << rv );

        rv = EVP_EncryptUpdate( ctx.get(), ciphertext, &len, plaintext, length );
        BREAK_IF( rv != 1, "Error: EVP_EncryptUpdate returned " << rv );

        ciphertext_len = len;

        rv = EVP_EncryptFinal_ex( ctx.get(), ciphertext + len, &len );
        BREAK_IF( rv != 1, "Error: EVP_EncryptFinal_ex returned " << rv );

        ciphertext_len += len;

    } while( false );

    return ciphertext_len;
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message
inline size_t decryptAES128ECB( const uint8_t* ciphertext, uint8_t* plaintext, const size_t length, const uint8_t* userkey ) {

    size_t plaintext_len = 0;

    do {
        int len = 0;

        std::shared_ptr<EVP_CIPHER_CTX> ctx( EVP_CIPHER_CTX_new(), []( EVP_CIPHER_CTX * ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        } );
        BREAK_IF( !ctx, "Error: Invalid ctx" );

        int rv = EVP_DecryptInit_ex( ctx.get(), EVP_aes_128_ecb(), nullptr, userkey, nullptr );
        BREAK_IF( rv != 1, "Error: EVP_DecryptInit_ex returned " << rv );

        rv = EVP_CIPHER_CTX_set_padding( ctx.get(), 0 );
        BREAK_IF( rv != 1, "Error: EVP_CIPHER_CTX_set_padding returned " << rv );

        rv = EVP_DecryptUpdate( ctx.get(), plaintext, &len, ciphertext, length );
        BREAK_IF( rv != 1, "Error: EVP_DecryptUpdate returned " << rv );

        plaintext_len = len;

        rv = EVP_DecryptFinal_ex( ctx.get(), plaintext + len, &len );
        BREAK_IF( rv != 1, "Error: EVP_DecryptFinal_ex returned " << rv );

        plaintext_len += len;

    } while( false );

    return plaintext_len;
}

}
