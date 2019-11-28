#include "set3.hpp"
#include "random.hpp"
#include "crypto.hpp"
#include "converter.hpp"

#include <vector>
#include <string>
#include <bitset>

std::string selectRandom() {
    const std::vector<std::string> strings = {
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    };

    // std::string hex = "0123456789abcdef0123456789abcdef";
    // return hex.substr( 0, randomnumber::get( hex.size() - 1 ) );
    return strings[randomnumber::get( strings.size() ) ];
}

using DecryptFunc = const std::function<bool( const Bytes& )>& ;

size_t guessPadding( const Bytes& data, DecryptFunc decrypt ) {

    size_t offset = data.size() - crypto::blockSize;
    // modify padding bytes by manipulating the penultimate block:
    // 0123456789012345|0123456789012345|0123cccccccccccc
    //                                 ^
    size_t padSize = 0;

    for( padSize = 0; padSize < crypto::blockSize; ++padSize ) {

        Bytes copy = data;

        std::bitset<8> byte = copy[offset - padSize - 1];
        byte.flip();

        copy[offset - padSize - 1] = byte.to_ulong();

        if( decrypt( copy ) ) {
            break;
        }
    }

    LOG( padSize );
    return padSize;
}

// change last non-padding byte to 'fix' padding again
std::tuple<uint8_t, Bytes> guessByte( const Bytes encrypted, const Bytes& incremented, const size_t padding, DecryptFunc decrypt ) {

    CHECK_EQ( encrypted.size(), incremented.size() );

    uint8_t secret = 0;
    size_t size = encrypted.size();
    size_t pos = size - padding - crypto::blockSize;
    Bytes copy = incremented;

    for( size_t byte = 0; byte < 256; ++byte ) {
        copy[pos] = byte;

        if( decrypt( copy ) ) {
            secret = encrypted[pos] ^ padding ^ byte;
            break;
        }
    }

    return std::tuple( secret, copy );
}

std::tuple<size_t, Bytes> incrementPadding( const Bytes& data, const size_t currentPadding ) {
    Bytes incremented = data;
    size_t newPadding = currentPadding + 1;

    // 0123456789012345|0123456789012345|0123dddddddddddd
    //                      ^^^^^^^^^^^^    d
    Bytes::iterator to = incremented.end() - crypto::blockSize;
    Bytes::iterator from = to - currentPadding;

    for( ; from != to; ++from ) {
        *from = *from ^ currentPadding ^ newPadding;
    }

    return std::tuple( newPadding, incremented );
}

// encrypt/decrypt with secret key
struct Crypto {
    // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
    Bytes key = { 0x23, 0xf4, 0x60, 0x65, 0x47, 0x0d, 0xa9, 0x12, 0xb7, 0x79, 0xa6, 0xfc, 0x45, 0x58, 0x9a, 0xce };
    std::string decrypted;

    struct EncryptedData {
        Bytes iv_ciphertext;
        size_t padSize;
    };

    EncryptedData encrypt() {
        decrypted = selectRandom();
        Bytes data( decrypted.cbegin(), decrypted.cend() );
        size_t padSize = crypto::blockSize - data.size() % crypto::blockSize;
        Bytes iv = crypto::genKey();
        Bytes encrypted = crypto::encryptAES128CBC( data, key, iv );
        return {iv + encrypted, padSize};
    }

    bool decrypt( const Bytes& iv_ciphertext ) const {
        try {
            Bytes iv = Bytes( iv_ciphertext.cbegin(), iv_ciphertext.cbegin() + crypto::blockSize );
            Bytes ciphertext = Bytes( iv_ciphertext.cbegin() + crypto::blockSize, iv_ciphertext.cend() );
            Bytes decrypted = crypto::decryptAES128CBC( ciphertext, key, iv );
            return true;
        } catch( std::invalid_argument ia ) {
            // LOG( ia.what() );
            return false;
        }
    }

    static bool cdecrypt( const Crypto& self, const Bytes& iv_ciphertext ) {
        return self.decrypt( iv_ciphertext );
    }
};

// https://en.wikipedia.org/wiki/Padding_oracle_attack
void challenge3_17() {
    Crypto crypto;
    DecryptFunc decrypt = [&crypto]( const Bytes & b ) { return crypto.decrypt( b ); };
    auto[encrypted, padding] = crypto.encrypt();
    LOG_DEBUG( encrypted << "\n" );
    size_t size = encrypted.size();

    size_t guessedPadding = guessPadding( encrypted, decrypt );
    CHECK_EQ( guessedPadding, padding );

    //                        // IV               // padding
    size_t guessSize = size - crypto::blockSize - guessedPadding;
    size_t currentPadding = guessedPadding;
    std::string decrypted;

    if( !guessSize ) { return; }

    LOG( "guess size " << guessSize );

    Bytes upgrade = encrypted;

    while( guessSize-- ) {

        if( currentPadding == crypto::blockSize ) {
            currentPadding = 0;
            size -= crypto::blockSize;
            encrypted.resize( size );
            upgrade = encrypted;
        }

        size_t newPadding;
        LOG_DEBUG( upgrade << "\n" );
        std::tie( newPadding, upgrade ) = incrementPadding( upgrade, currentPadding );
        LOG_DEBUG( upgrade << "\n" );

        uint8_t secret;
        std::tie( secret, upgrade ) = guessByte( encrypted, upgrade, newPadding, decrypt );
        decrypted.push_back( secret );
        LOG_DEBUG( upgrade << "\n" );

        currentPadding = newPadding;
    }

    std::reverse( decrypted.begin(), decrypted.end() );
    Bytes binary = converter::base64ToBinary( decrypted );
    LOG( std::string( binary.cbegin(), binary.cend() ) );
    CHECK_EQ( decrypted, crypto.decrypted );
}



void challenge3_18() {
    Bytes encrypted = converter::base64ToBinary( "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==" );
    std::string key = "YELLOW SUBMARINE";
    Bytes vkey( key.cbegin(), key.cend() );

    Bytes vdecrypted = crypto::decryptAES128CTR( encrypted, vkey, 0 );
    std::string decrypted( vdecrypted.cbegin(), vdecrypted.cend() );
    CHECK_EQ( decrypted, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby " );

    Bytes reencrypted = crypto::encryptAES128CTR( vdecrypted, vkey, 0 );
    CHECK_EQ( reencrypted, encrypted );
}
