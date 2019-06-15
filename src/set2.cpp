#include "set2.hpp"

#include "utils.hpp"
#include "crypto.hpp"
#include "converter.hpp"
#include "log.hpp"

void challenge2_9() {
    LOG( "Running challenge 2.9" );

    std::string text = "YELLOW SUBMARINE";

    std::string expected20 = "YELLOW SUBMARINE\x04\x04\x04\x04";
    std::string padded20 = crypto::padPKCS7( text, 20 );
    CHECK_EQ( padded20, expected20 );
    std::string unpadded20 = crypto::unpadPKCS7( padded20 );
    CHECK_EQ( unpadded20, text );

    std::string expected16 = "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
    std::string padded16 = crypto::padPKCS7( text, 16 );
    CHECK_EQ( padded16, expected16 );
    std::string unpadded16 = crypto::unpadPKCS7( padded16 );
    CHECK_EQ( unpadded16, text );
}

void challenge2_10() {
    LOG( "Running challenge 2.10" );

    std::string key = "YELLOW SUBMARINE";
    Bytes vkey( key.cbegin(), key.cend() );

    std::string iv =  "0123456789abcdef";
    Bytes viv( iv.cbegin(), iv.cend() );

    std::string plain = "O THANKS!!! ITS SO MUCH EASIER TO WRITE NOW!!!!!!!";
    Bytes vPlain( plain.begin(), plain.end() );

    // ECB
    {
        // echo -n 'O THANKS!!! ITS SO MUCH EASIER TO WRITE NOW!!!!!!!' | openssl enc -aes-128-ecb -K "$(echo -n 'YELLOW SUBMARINE' | xxd -p)" | xxd -p -c 1000
        Bytes encrypted = crypto::encryptAES128ECB( vPlain, vkey );
        CHECK_EQ( encrypted, converter::hexToBinary( "2f08fcaadf5183afb9041f560797a7836cec1f18f54052a152349d4b970a31f162ec1ff2a8e0dfcfc7bd2e0e9cacead6ea009ac545c6a406ddcc009f5037bc50" ) );
        Bytes decrypted = crypto::decryptAES128ECB( encrypted, vkey );
        CHECK_EQ( vPlain, decrypted );
    }

    // CBC
    {
        // echo -n 'O THANKS!!! ITS SO MUCH EASIER TO WRITE NOW!!!!!!!' | openssl enc -aes-128-cbc -K "$(echo -n 'YELLOW SUBMARINE' | xxd -p)" -iv "$(echo -n '0123456789abcdef' | xxd -p)" | xxd -p -c 1000
        Bytes encrypted = crypto::encryptAES128CBC( vPlain, vkey, viv );
        CHECK_EQ( encrypted, converter::hexToBinary( "ba41c7ea8826dfb3df62c1b73894b28179034a4fedf16983462e54b34ddeb0e7ce07383fa833a863321f7fa5b867dde6cbb402105357caf7d75463db95efabd6" ) );
        Bytes decrypted = crypto::decryptAES128CBC( encrypted, vkey, viv );
        CHECK_EQ( vPlain, decrypted );
    }

    // challenge itself
    {
        // base64 -d 2_10.txt | openssl enc -d -aes-128-cbc -K "$(echo -n 'YELLOW SUBMARINE' | xxd -p)" -iv "00000000000000000000000000000000"
        Bytes encrypted = utils::fromBase64File( "2_10.txt" );
        Bytes viv2( 16, 0 );
        Bytes decrypted = crypto::decryptAES128CBC( encrypted, vkey, viv2 );
        std::string plain( decrypted.cbegin(), decrypted.cend() );

        std::string expected = "I'm back and I'm ringin' the bell \n"
                               "A rockin' on the mike while the fly girls yell \n";
        plain.resize( expected.size() );
        CHECK_EQ( plain, expected );
    }
}
