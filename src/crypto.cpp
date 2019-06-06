#include <memory>

#include "crypto.hpp"

#include "openssl/evp.h"

#define BREAK_IF( COND, MSG ) if( ( COND ) ) { LOG( MSG ); break; }

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message
int decrypt( const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext ) {

    int plaintext_len = 0;

    do {
        int len = 0;

        std::shared_ptr<EVP_CIPHER_CTX> ctx( EVP_CIPHER_CTX_new(), []( EVP_CIPHER_CTX * ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        } );
        BREAK_IF( !ctx, "Error: Invalid ctx" );

        int rv = EVP_DecryptInit_ex( ctx.get(), EVP_aes_128_ecb(), nullptr, key, iv );
        BREAK_IF( rv != 1, "Error: EVP_DecryptInit_ex returned " << rv );

        rv = EVP_DecryptUpdate( ctx.get(), plaintext, &len, ciphertext, ciphertext_len );
        BREAK_IF( rv != 1, "Error: EVP_DecryptUpdate returned " << rv );

        plaintext_len = len;

        rv = EVP_DecryptFinal_ex( ctx.get(), plaintext + len, &len );
        BREAK_IF( rv != 1, "Error: EVP_DecryptFinal_ex returned " << rv );

        plaintext_len += len;

    } while( false );

    return plaintext_len;
}

std::string crypto::decryptAES128ECB( const Bytes& data, const Bytes& key ) {

    unsigned char* c_iv = nullptr ; //const_cast<unsigned char*>( key.data() );
    unsigned char* c_key = const_cast<unsigned char*>( key.data() );

    unsigned char* c_ciphertext = const_cast<unsigned char*>( data.data() );;
    int ciphertext_len = data.size();

    std::string plain( ciphertext_len, '\0' );
    unsigned char* c_plaintext = reinterpret_cast<unsigned char*>( plain.data() );

    int len = decrypt( c_ciphertext, ciphertext_len, c_key, c_iv, c_plaintext );

    plain.resize( ( size_t )len );
    return plain;
}
