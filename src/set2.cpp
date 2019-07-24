#include "set2.hpp"

#include <optional>

#include "utils.hpp"
#include "crypto.hpp"
#include "cracker.hpp"
#include "converter.hpp"
#include "log.hpp"

void challenge2_9() {
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

void challenge2_11() {
    Bytes key = crypto::genKey();
    CHECK_EQ( key.size(), 16 );

    Bytes data( 4096, 0 );

    // write encrypted data to file
    auto dump = []( const crypto::Encrypted & enc ) {
        static size_t i = 0;
        std::stringstream filename;
        filename << enc.type;
        filename << "_";
        filename.width( 2 );
        filename.fill( '0' );
        filename << ++i;
        filename << ".enc";
        utils::toFile( filename.str(), enc.bytes );
    };

    // detect if the 4k zero string is ECB or CBC encrypted
    for( size_t i = 0; i < 20; ++i ) {
        crypto::Encrypted enc = crypto::encryptECBOrCBC( data );
        dump( enc ); // for analysis with xz compression (./scripts/analyze_ecb_cbc.sh)

        std::optional<crypto::Encrypted::Type> guess = cracker::detectECBorCBC( enc.bytes, 16 );
        CHECK_EQ( enc.type, *guess );
    }
}

void challenge2_12() {
    // 1 detect block size
    cracker::GuessedSize guess = cracker::guessBlockSize( crypto::encryptECBWithSecretPrefix );
    CHECK_EQ( guess.blockSize, 16 );
    CHECK_EQ( guess.extra, 138 );

    // 2 detect ECB mode
    Bytes data( 4096, 0 );
    Bytes enc = crypto::encryptECBWithSecretPrefix( data );
    std::optional<crypto::Encrypted::Type> opt = cracker::detectECBorCBC( enc, guess.blockSize );
    CHECK_EQ( *opt, crypto::Encrypted::Type::ECB );

    // 3 guess first encrypted character
    std::string secret;
    secret.reserve( guess.extra );
    size_t blocks = guess.extra / guess.blockSize;
    Bytes data3( guess.blockSize, 0 );

    size_t k = 0;

    // 4,5,6 guess one byte after another
    for( size_t i = 0; i <= blocks; ++i ) {
        for( size_t j = 1; j <= guess.blockSize; ++j ) {

            Bytes data2( guess.blockSize - j, 0 );
            Bytes enc1 = crypto::encryptECBWithSecretPrefix( data2 );

            for( uint8_t sec = 0; sec != std::numeric_limits<uint8_t>::max(); ++sec ) {
                data3.back() = sec;
                Bytes enc2 = crypto::encryptECBWithSecretPrefix( data3 );

                Bytes first1( enc1.cbegin() + guess.blockSize * i, enc1.cbegin() + guess.blockSize * ( i + 1 ) );
                Bytes first2( enc2.cbegin(), enc2.cbegin() + guess.blockSize );

                if( first1 == first2 ) {
                    // LOG( "[" << ( char )sec << "]" );
                    secret.push_back( ( char )sec );
                    // shift forward
                    std::rotate( data3.begin(), data3.begin() + 1, data3.end() );
                    break;
                }
            }

            // stop after all bytes are read
            if( ++k == guess.extra ) {
                goto end;
            }
        }
    }

end:
    void();

    std::string expected = "Rollin' in my 5.0\n"
                           "With my rag-top down so my hair can blow\n"
                           "The girlies on standby waving just to say hi\n"
                           "Did you stop? No, I just drove by\n";
    CHECK_EQ( secret, expected );

}

void challenge2_13() {
    // test parser
    {
        std::string params = "foo=bar&====&&baz=qux&zap=zazzle&";
        std::map<std::string, std::string> parsed = utils::parseGETParams( params );
        std::map<std::string, std::string> expected = { { "foo", "bar" }, { "baz", "qux" }, {"zap", "zazzle"} };
        CHECK_EQ( parsed, expected );
    }

    // test profile generator
    {
        std::string request = utils::profileFor( "hase&@mai=l.com" );
        std::string expected = "email=hase@mail.com&uid=10&role=user";
        CHECK_EQ( request, expected );
    }

    {
        std::string request = utils::profileFor( "hase@mail.com" );
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x12, 0x99, 0x87, 0x0f, 0x15, 0x1a, 0xaa, 0x18, 0x21, 0x64, 0x2e, 0xe8, 0xd8, 0x66, 0x7d, 0xde };
        Bytes data( request.cbegin(), request.cend() );
        Bytes encrypted = crypto::encryptAES128ECB( data, key );
        Bytes decrypted = crypto::decryptAES128ECB( encrypted, key );
        std::string request2( decrypted.cbegin(), decrypted.cend() );
        std::map<std::string, std::string> parsed = utils::parseGETParams( request2 );
        LOG( parsed );
    }
}

