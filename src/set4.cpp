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
