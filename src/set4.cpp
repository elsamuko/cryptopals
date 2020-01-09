#include "set4.hpp"

#include "utils.hpp"
#include "crypto.hpp"
#include "random.hpp"
#include "converter.hpp"
#include "hash.hpp"
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

void challenge4_27() {
    // encrypt/decrypt with secret key
    struct {
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x0c, 0xc8, 0xdf, 0x18, 0x31, 0x4d, 0x46, 0x03, 0x8d, 0x53, 0x65, 0x17, 0xa7, 0x56, 0x03, 0x2d };

        Bytes pack( const std::string& userdata ) const {
            std::string request = utils::generateGETRequest( userdata );
            Bytes data( request.cbegin(), request.cend() );
            Bytes encrypted = crypto::encryptAES128CBC( data, key, key );
            return encrypted;
        }

        std::string decrypt( const Bytes& encrypted ) const {
            Bytes decrypted = crypto::decryptAES128CBC( encrypted, key, key );
            std::string request( decrypted.cbegin(), decrypted.cend() );
            return request;
        }

        std::optional<std::string> isBad( const Bytes& encrypted ) const {
            std::string request = decrypt( encrypted );

            if( !utils::isAscii( request ) ) {
                return request;
            }

            return {};
        }
    } Packer;

    // ensure encrypted data is min 3 blocks big
    // AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    std::string userdata( 3 * crypto::blockSize, 'A' );
    Bytes encrypted = Packer.pack( userdata );
    CHECK( !Packer.isBad( encrypted ) );

    // C_1, C_2, C_3 -> C_1, 0, C_1
    {
        // nullify 2nd block
        for( size_t pos = crypto::blockSize; pos < 2 * crypto::blockSize; ++pos ) {
            encrypted[pos] = 0;
        }

        // copy first to third block
        for( size_t pos = 0; pos < crypto::blockSize; ++pos ) {
            encrypted[pos + 2 * crypto::blockSize] = encrypted[pos];
        }
    }
    auto isBad = Packer.isBad( encrypted );
    CHECK( isBad );

    if( !isBad ) { return; }

    std::string error = isBad.value();

    // P'_1 XOR P'_3
    Bytes p1( error.cbegin(), error.cbegin() + crypto::blockSize );
    Bytes p3( error.cbegin() + 2 * crypto::blockSize, error.cbegin() + 3 * crypto::blockSize );
    Bytes key = crypto::XOR( p1, p3 );
    CHECK_EQ( key, Packer.key );

}

void challenge4_28() {
    // verify sha1 code
    std::map<std::string, std::string> hashes = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"Hallo", "59d9a6df06b9f610f7db8e036896ed03662d168f"},
        {std::string( 127, 'A' ), "8c8393ac8939430753d7cb568e2f2237bc62d683"},
    };

    for( auto&& hash : hashes ) {
        Bytes data = bytes( hash.first );
        Bytes sha1 = hash::sha1( data );
        CHECK_EQ( converter::binaryToHex( sha1 ), hash.second );
    }

    // generate sha1 MAC
    Bytes key = crypto::genKey();
    Bytes message = randombuffer::get( 100 );
    Bytes mac = crypto::macSha1( message, key );

    // flip every bit of the message and verify its MAC changed
    for( size_t i = 0; i < 800; ++i ) {
        size_t pos = i / 8;
        uint8_t flip = 1 << i % 8;

        message[pos] ^= flip;
        Bytes newMac = crypto::macSha1( message, key );
        CHECK_NE( newMac, mac );

        // restore original message
        message[pos] ^= flip;
    }

    // verify, that a random generated key cannot generate the same MAC
    for( size_t i = 0; i < 1000; ++i ) {
        Bytes newKey = crypto::genKey();
        Bytes newMac = crypto::macSha1( message, newKey );
        CHECK_NE( newMac, mac );
    }
}
