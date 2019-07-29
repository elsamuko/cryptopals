#pragma once

#include <memory>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "log.hpp"

#define BREAK_IF( COND, MSG ) if( ( COND ) ) { LOG( MSG ); break; }

namespace openssl {

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
inline int encrypt( const unsigned char* plaintext, const int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext ) {

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
inline int decrypt( const unsigned char* ciphertext, const int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext ) {

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
