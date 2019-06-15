#include "set2.hpp"

#include "utils.hpp"
#include "crypto.hpp"
#include "converter.hpp"
#include "log.hpp"

void challenge2_9() {
    LOG( "Running challenge 2.9" );

    std::string text = "YELLOW SUBMARINE";
    std::string expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
    std::string padded = crypto::padPKCS7( text, 20 );

    CHECK_EQ( padded, expected );
}

void challenge2_10() {
    LOG( "Running challenge 2.10" );

    std::string key = "YELLOW SUBMARINE";
    Bytes vkey( key.cbegin(), key.cend() );

    std::string iv =  "0123456789abcdef";
    Bytes viv( iv.cbegin(), iv.cend() );

    std::string plain = "0123456789abcdef";
    Bytes vPlain( plain.begin(), plain.end() );

    // ECB
    {
        // echo -n "0123456789abcdef" | openssl enc -nopad -aes-128-ecb -K "$(echo -n 'YELLOW SUBMARINE' | xxd -p)" | xxd -p -c 1000
        Bytes encrypted = crypto::encryptAES128ECB( vPlain, vkey );
        CHECK_EQ( encrypted, converter::hexToBinary( "201e802f7b6ace6f6cd0a743ba78aead" ) );
        Bytes decrypted = crypto::decryptAES128ECB( encrypted, vkey );
        CHECK_EQ( vPlain, decrypted );
    }

    // CBC
    {
        // echo -n "0123456789abcdef" | openssl enc -nopad -aes-128-cbc -K "$(echo -n 'YELLOW SUBMARINE' | xxd -p)" -iv "$(echo -n '0123456789abcdef' | xxd -p)" | xxd -p -c 1000
        Bytes encrypted = crypto::encryptAES128CBC( vPlain, vkey, viv );
        CHECK_EQ( encrypted, converter::hexToBinary( "76d1cb4bafa246e2e3af035d6c13c372" ) );
        Bytes decrypted = crypto::decryptAES128CBC( encrypted, vkey, viv );
        CHECK_EQ( vPlain, decrypted );
    }
}
