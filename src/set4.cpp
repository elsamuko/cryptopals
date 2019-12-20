#include "set4.hpp"

#include "utils.hpp"
#include "crypto.hpp"
#include "random.hpp"
#include "log.hpp"


struct Crypto {
    // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
    Bytes key = { 0x22, 0x1c, 0xc1, 0x81, 0x63, 0xeb, 0x3a, 0x84, 0x68, 0x7c, 0x66, 0xf8, 0xde, 0x4e, 0x79, 0x17 };
    uint64_t nonce = 9504;
    Bytes encrypted;

    Bytes edit( const size_t& offset, const Bytes& replacement ) {
        return crypto::editAES128CTR( encrypted, offset, replacement, key, nonce );
    }

    Bytes encrypt( const Bytes& plain ) {
        encrypted = crypto::encryptAES128CTR( plain, key, nonce );
        return encrypted;
    }
};

void testReplacement() {
    Bytes key( bytes( "YELLOW SUBMARINE" ) );
    Bytes clear( bytes( "Testing text replacement" ) );
    uint64_t nonce = 12309;
    Bytes encrypted( crypto::encryptAES128CTR( clear, key, nonce ) );

    Bytes edited = crypto::editAES128CTR( encrypted, 8, bytes( "hase" ), key, nonce );
    Bytes decrypted = crypto::decryptAES128CTR( edited, key, nonce );

    Bytes expected( bytes( "Testing hase replacement" ) );
    CHECK_EQ( decrypted, expected );
}

void challenge4_25() {
    Bytes encrypted = utils::fromBase64File( "1_7.txt" );
    Bytes key( bytes( "YELLOW SUBMARINE" ) );
    Bytes plain = crypto::decryptAES128ECB( encrypted, key );

    Crypto crypto;
    Bytes stream = crypto.encrypt( plain );

    testReplacement();

    // replace secret text with zeros to get XOR stream
    Bytes replacement( stream.size(), 0 );
    Bytes replaced = crypto.edit( 0, replacement );
    Bytes decrypted = crypto::XOR( stream, replaced );

    CHECK_EQ( plain, decrypted );
}

void challenge4_26() {
    // encrypt/decrypt with secret key
    struct {
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x0c, 0xc8, 0xdf, 0x18, 0x31, 0x4d, 0x46, 0x03, 0x8d, 0x53, 0x65, 0x17, 0xa7, 0x56, 0x03, 0x2d };
        // dd if=/dev/urandom bs=1 count=8 status=none | od -A none -t u8
        uint64_t nonce = 14314387627995711828u;

        Bytes pack( const std::string& userdata ) const {
            std::string request = utils::generateGETRequest( userdata );
            Bytes data( request.cbegin(), request.cend() );
            Bytes encrypted = crypto::encryptAES128CTR( data, key, nonce );
            return encrypted;
        }

        std::string decrypt( const Bytes& encrypted ) const {
            Bytes decrypted = crypto::decryptAES128CTR( encrypted, key, nonce );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            return request;
        }

        bool isAdmin( const Bytes& encrypted ) const {
            Bytes decrypted = crypto::decryptAES128CTR( encrypted, key, nonce );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            bool admin = utils::isAdmin( request );
            return admin;
        }
    } Packer;

    std::string userdata = "|admin|true";
    Bytes encrypted = Packer.pack( userdata );
    LOG( Packer.decrypt( encrypted ).substr( 32, 16 ) );

    // search for bytes at pos1 and pos2, which will change the decrypted text from
    // |admin|true
    // to
    // ;admin=true
    size_t pos1 = 32; // position of first '|'
    size_t pos2 = 38; // position of second '|'
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
