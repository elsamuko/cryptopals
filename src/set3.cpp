#include "set3.hpp"
#include "random.hpp"
#include "crypto.hpp"

#include <vector>
#include <string>

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

    return strings[randomnumber::get( strings.size() ) ];
}

void challenge3_17() {
    // encrypt/decrypt with secret key
    struct Crypto {
        // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
        Bytes key = { 0x23, 0xf4, 0x60, 0x65, 0x47, 0x0d, 0xa9, 0x12, 0xb7, 0x79, 0xa6, 0xfc, 0x45, 0x58, 0x9a, 0xce };

        struct EncryptedData {
            Bytes iv;
            Bytes ciphertext;
            size_t padSize;
        };

        EncryptedData encrypt() {
            std::string request = selectRandom();
            Bytes data( request.cbegin(), request.cend() );
            size_t padSize = crypto::blockSize - data.size() % crypto::blockSize;
            Bytes iv = crypto::genKey();
            Bytes encrypted = crypto::encryptAES128CBC( data, key, iv );
            return {iv, encrypted, padSize};
        }

        bool decrypt( const EncryptedData& encrypted ) {
            try {
                Bytes decrypted = crypto::decryptAES128CBC( encrypted.ciphertext, key, encrypted.iv );
                return true;
            } catch( std::invalid_argument ia ) {
                // LOG( ia.what() );
                return false;
            }
        }
    } crypto;

    Crypto::EncryptedData encrypted = crypto.encrypt();
    size_t pos = encrypted.ciphertext.size() - crypto::blockSize; // modify padding bytes

    // 0123456789012345|0123456789012345|0123cccccccccccc
    //                                 ^
    size_t padSize = 0;

    for( padSize = 0; padSize <= crypto::blockSize; ++padSize ) {

        Crypto::EncryptedData copy = encrypted;

        copy.ciphertext[pos - padSize - 1] = 0;

        if( crypto.decrypt( copy ) ) {
            break;
        }
    }

    LOG( padSize );
    CHECK_EQ( padSize, encrypted.padSize );
}
