#include "set2.hpp"

#include "utils.hpp"
#include "crypto.hpp"
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

    std::string plain = "Hello World!";
    Bytes encrypted = crypto::encryptAES128ECB( plain, vkey );
    std::string decrypted = crypto::decryptAES128ECB( encrypted, vkey );
    CHECK_EQ( plain, decrypted );

}
