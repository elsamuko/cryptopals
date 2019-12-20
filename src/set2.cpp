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
    cracker::GuessedSize guess = cracker::guessBlockSize( crypto::encryptECBWithSecretSuffix );
    CHECK_EQ( guess.blockSize, 16 );
    CHECK_EQ( guess.suffix, 138 );

    // 2 detect ECB mode
    Bytes data( 4096, 0 );
    Bytes enc = crypto::encryptECBWithSecretSuffix( data );
    std::optional<crypto::Encrypted::Type> opt = cracker::detectECBorCBC( enc, guess.blockSize );
    CHECK_EQ( *opt, crypto::Encrypted::Type::ECB );

    // 3 guess first encrypted character
    std::string secret;
    secret.reserve( guess.suffix );
    size_t blocks = 1 + guess.suffix / guess.blockSize;
    Bytes data3( guess.blockSize, 0 );

    size_t guessed = 0;

    // 4,5,6 guess one byte after another
    for( size_t i = 0; i < blocks; ++i ) {
        for( size_t j = 1; j <= guess.blockSize; ++j ) {

            // 000000000000000S UFFIX
            Bytes data2( guess.blockSize - j, 0 );
            Bytes enc1 = crypto::encryptECBWithSecretSuffix( data2 );

            for( uint8_t sec = 0; sec != std::numeric_limits<uint8_t>::max(); ++sec ) {
                data3.back() = sec;
                Bytes enc2 = crypto::encryptECBWithSecretSuffix( data3 );

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
            if( ++guessed == guess.suffix ) {
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

    // encrypt/decrypt with secret key
    struct {
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x12, 0x99, 0x87, 0x0f, 0x15, 0x1a, 0xaa, 0x18, 0x21, 0x64, 0x2e, 0xe8, 0xd8, 0x66, 0x7d, 0xde };

        Bytes encrypt( const std::string& request ) {
            Bytes data( request.cbegin(), request.cend() );
            Bytes encrypted = crypto::encryptAES128ECB( data, key );
            return encrypted;
        }

        std::string decrypt( const Bytes& encrypted ) {
            Bytes decrypted = crypto::decryptAES128ECB( encrypted, key );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            return request;
        }
    } Crypto;

    // get encrypted data for first two ECB blocks, which end with "role="
    // email=XXXXXXXXXXXXX&uid=10&role=
    Bytes firstPart;
    Bytes padding;
    {
        std::string rest = "email=&uid=10&role=";
        std::string fillMail = "bunny@mail.it";
        CHECK_EQ( fillMail.size() + rest.size(), 32 );

        std::string request = utils::profileFor( fillMail );
        Bytes encrypted = Crypto.encrypt( request );
        CHECK_EQ( encrypted.size(), 48 );
        firstPart.assign( encrypted.cbegin(), encrypted.cbegin() + 32 );
        padding.assign( encrypted.cbegin() + 32, encrypted.cend() );
    }

    // get encrypted data for second ECB block which starts with "admin"
    // email=XXXXXXXXXXadmin&uid=10&role=user
    //                 ^
    Bytes secondPart;
    {
        std::string rest = "email=";
        std::string admin = "admin";
        std::string fillMail = "XXXXXXXXXX" + admin;
        CHECK_EQ( fillMail.size() + rest.size(), 16 + admin.size() );

        std::string request = utils::profileFor( fillMail );
        Bytes encrypted = Crypto.encrypt( request );
        CHECK( encrypted.size() > 32 );
        secondPart.assign( encrypted.cbegin() + 16, encrypted.cbegin() + 32 );
    }

    // merge two parts as
    // email=bunny@mail.it&uid=10&role=admin&uid=10&rol
    {
        Bytes merged = firstPart + secondPart + padding;
        CHECK_EQ( merged.size(), 64 );
        std::string decrypted = Crypto.decrypt( merged );
        LOG( decrypted );
        std::map<std::string, std::string> parsed = utils::parseGETParams( decrypted );
        CHECK_EQ( parsed["role"], "admin" );
    }
}

void challenge2_14() {
    // detect block size and prefix/suffix size assuming the random prefix is static
    cracker::GuessedSize guess = cracker::guessBlockSize( crypto::encryptECBWithRandomPrefixAndSecretSuffix );
    CHECK_EQ( guess.blockSize, 16 );
    LOG( "prefix: " << guess.prefix );
    LOG( "suffix: " << guess.suffix );

    // detect ECB mode
    Bytes data( 4096, 0 );
    Bytes enc = crypto::encryptECBWithRandomPrefixAndSecretSuffix( data );
    std::optional<crypto::Encrypted::Type> opt = cracker::detectECBorCBC( enc, guess.blockSize );
    CHECK_EQ( *opt, crypto::Encrypted::Type::ECB );

    // guess last encrypted character
    std::string secret;
    secret.reserve( guess.suffix );

    // PREFIX0000000000
    size_t rest = ( guess.blockSize - guess.prefix % guess.blockSize ) % guess.blockSize;
    Bytes data3( rest + guess.blockSize, 0 );

    // max blocks we have to iterate to guess the whole secret string
    size_t blocks = 1 + guess.suffix / guess.blockSize;

    // offset to 'guessing block'
    size_t offset = guess.prefix / guess.blockSize + ( ( guess.prefix % guess.blockSize ) ? 1 : 0 );
    LOG( "Guessing " << blocks << " blocks starting with " << offset << " blocks offset" );

    size_t guessed = 0;

    // guess one byte after another
    for( size_t i = 0; i < blocks; ++i ) {
        for( size_t j = 1; j <= guess.blockSize; ++j ) {

            // PREFIX0000000000 000000000000000S UFFIX
            Bytes data2( rest + guess.blockSize - j, 0 );
            Bytes enc1 = crypto::encryptECBWithRandomPrefixAndSecretSuffix( data2 );

            for( uint8_t sec = 0; sec != std::numeric_limits<uint8_t>::max(); ++sec ) {
                data3.back() = sec;
                Bytes enc2 = crypto::encryptECBWithRandomPrefixAndSecretSuffix( data3 );

                Bytes first1( enc1.cbegin() + guess.blockSize * ( offset + i + 0 ),
                              enc1.cbegin() + guess.blockSize * ( offset + i + 1 ) );
                Bytes first2( enc2.cbegin() + guess.blockSize * ( offset + 0 ),
                              enc2.cbegin() + guess.blockSize * ( offset + 1 ) );

                if( first1 == first2 ) {
                    // LOG( "[" << ( char )sec << "]" );
                    secret.push_back( ( char )sec );
                    // shift forward
                    std::rotate( data3.begin(), data3.begin() + 1, data3.end() );
                    break;
                }
            }

            // stop after all bytes are read
            if( ++guessed == guess.suffix ) {
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

void challenge2_15() {
    CHECK_EQ( "ICE ICE BABY", crypto::unpadPKCS7( std::string( "ICE ICE BABY\x01" ) ) );
    CHECK_EQ( "ICE ICE BABY", crypto::unpadPKCS7( std::string( "ICE ICE BABY\x04\x04\x04\x04" ) ) );
    CHECK_THROW( crypto::unpadPKCS7( std::string( "ICE ICE BABY\x05\x05\x05\x05" ) ) );
    CHECK_THROW( crypto::unpadPKCS7( std::string( "ICE ICE BABY\x01\x02\x03\x04" ) ) );
}

void challenge2_16() {

    std::string userdata = "HASE";
    std::string request = utils::generateGETRequest( userdata );
    CHECK_EQ( request, "comment1=cooking%20MCs;userdata=HASE;comment2=%20like%20a%20pound%20of%20bacon" );

    // encrypt/decrypt with secret key
    struct {
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x0c, 0xc8, 0xdf, 0x18, 0x31, 0x4d, 0x46, 0x03, 0x8d, 0x53, 0x65, 0x17, 0xa7, 0x56, 0x03, 0x2d };
        Bytes iv  = { 0x2b, 0x02, 0x6a, 0xb4, 0x30, 0x94, 0x64, 0xcb, 0x4d, 0x29, 0x62, 0x6c, 0xaa, 0xc7, 0x59, 0xac };

        Bytes pack( const std::string& userdata ) const {
            std::string request = utils::generateGETRequest( userdata );
            Bytes data( request.cbegin(), request.cend() );
            Bytes encrypted = crypto::encryptAES128CBC( data, key, iv );
            return encrypted;
        }

        std::string decrypt( const Bytes& encrypted ) const {
            Bytes decrypted = crypto::decryptAES128CBC( encrypted, key, iv );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            return request;
        }

        bool isAdmin( const Bytes& encrypted ) const {
            Bytes decrypted = crypto::decryptAES128CBC( encrypted, key, iv );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            bool admin = utils::isAdmin( request );
            return admin;
        }
    } Packer;

    userdata = "|admin|true";
    Bytes encrypted = Packer.pack( userdata );
    LOG( Packer.decrypt( encrypted ).substr( 32, 16 ) );

    // search for bytes at pos1 and pos2, which will change the decrypted text from
    // |admin|true
    // to
    // ;admin=true
    size_t pos1 = 16; // position of first '|' minus block size
    size_t pos2 = 22; // position of second '|' minus block size
    bool isAdmin = false;

    for( size_t flip1 = 0; flip1 < 256; ++flip1 ) {
        for( size_t flip2 = 0; flip2 < 256; ++flip2 ) {

            encrypted[pos1] = ( Byte )flip1;
            encrypted[pos2] = ( Byte )flip2;

            if( Packer.isAdmin( encrypted ) ) {
                isAdmin = true;
                LOG( Packer.decrypt( encrypted ).substr( 32, 16 ) );
                goto stop;
            }
        }
    }

stop:
    CHECK( isAdmin );
}
