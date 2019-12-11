#include "set3.hpp"
#include "random.hpp"
#include "crypto.hpp"
#include "converter.hpp"

#include <vector>
#include <string>
#include <bitset>
#include <array>
#include <ctime>

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

std::tuple<std::vector<Bytes>, std::vector<Bytes>> encryptedStrings( const std::string& filename ) {
    const std::vector<std::string> strings  = utils::fromFile( filename );

    // dd if=/dev/urandom bs=1 count=16 status=none | xxd -i -c 1000
    Bytes key = { 0x60, 0x6e, 0xeb, 0x27, 0x29, 0xb0, 0x67, 0xdc, 0xad, 0x0e, 0xa5, 0xb3, 0x87, 0xb1, 0x35, 0x52 };

    std::vector<Bytes> encrypted;
    std::vector<Bytes> clear;
    encrypted.reserve( strings.size() );
    clear.reserve( strings.size() );

    for( const std::string& base64 : strings ) {
        Bytes text = converter::base64ToBinary( base64 );
        clear.push_back( text );

        Bytes ctr = crypto::encryptAES128CTR( text, key, 0 );
        encrypted.push_back( ctr );
    }

    return std::make_tuple( clear, encrypted );
}

size_t maxLength( const std::vector<Bytes>& data ) {
    size_t vmax = 0;

    for( const Bytes& bytes : data ) {
        vmax = std::max( vmax, bytes.size() );
    }

    return vmax;
}

using FirstGuesses = std::array<Bytes, 6>;

FirstGuesses guessByLetterFrequency( const std::vector<Bytes>& encrypted ) {

    size_t vmax = maxLength( encrypted );

    FirstGuesses crypt;

    for( Bytes& b : crypt ) {
        b.reserve( vmax );
    }

    size_t pos = 0;

    while( pos < vmax ) {

        Bytes bytes;
        bytes.reserve( encrypted.size() );

        // get pos byte of every string
        for( const Bytes& one : encrypted ) {
            if( one.size() > pos ) {
                bytes.push_back( one[pos] );
            }
        }

        uint8_t key = 0;
        std::vector<std::pair<float, Byte>> guesses;
        guesses.reserve( 256 );

        do {
            Bytes text = crypto::XOR( bytes, key );

            float v = utils::isEnglishText( text );
            guesses.emplace_back( v, key );

        } while( ++key );

        std::sort( guesses.begin(), guesses.end() );

        for( size_t i = 0; i < crypt.size(); ++i ) {
            crypt[i].push_back( guesses[255 - i].second );
        }

        ++pos;
    }

    return crypt;
}

Bytes guessByWordFrequency( const std::vector<Bytes>& encrypted, const FirstGuesses& crypts ) {
    Bytes bestCrypt = crypts[0];
    float bestGuess = -1000.f;

    for( size_t pos = 0; pos < crypts[0].size(); ++pos ) {

        size_t bestPos = 0;

        for( size_t gPos = 0; gPos < crypts.size(); ++gPos ) {

            bestCrypt[pos] = crypts[gPos][pos];
            std::vector<Bytes> text = crypto::XOR( encrypted, bestCrypt );
            float v = utils::areEnglishSentences( text );

            if( v > bestGuess ) {
                bestPos = gPos;
                bestGuess = v;
            }
        }

        bestCrypt[pos] = crypts[bestPos][pos];
    }

    return bestCrypt;
}

void challenge3_19() {
    auto[ clears, encrypted ] = encryptedStrings( "3_19.txt" );
    CHECK( !encrypted.empty() );

    FirstGuesses crypt = guessByLetterFrequency( encrypted );
    Bytes bestCrypt = guessByWordFrequency( encrypted, crypt );

    for( size_t i = 0; i < clears.size(); ++i ) {
        std::string decrypted = str( crypto::XOR( encrypted[i], bestCrypt ) );
        std::string clear = str( clears[i] );

        // check for equality of first 30 chars, further guesses are unreliable
        CHECK_EQ( decrypted.substr( 0, 30 ), clear.substr( 0, 30 ) );

        // display the ones, we couldn't fully guess
        if( decrypted != clear ) {
            LOG_DEBUG( clear );
            LOG_DEBUG( decrypted );
        }
    }
}

void challenge3_20() {
    auto[ clears, encrypted ] = encryptedStrings( "3_20.txt" );
    CHECK( !encrypted.empty() );

    FirstGuesses crypt = guessByLetterFrequency( encrypted );
    Bytes bestCrypt = guessByWordFrequency( encrypted, crypt );

    for( size_t i = 0; i < clears.size(); ++i ) {
        std::string decrypted = str( crypto::XOR( encrypted[i], bestCrypt ) );
        std::string clear = str( clears[i] );

        // check for equality of first 100 chars, further guesses are unreliable
        CHECK_EQ( decrypted.substr( 0, 100 ), clear.substr( 0, 100 ) );

        // display the ones, we couldn't fully guess
        if( decrypted != clear ) {
            LOG_DEBUG( clear );
            LOG_DEBUG( decrypted );
        }
    }
}

void challenge3_21() {
    uint32_t seed = 7373;
    std::seed_seq seq{ seed };
    std::mt19937 gen( seq );
    Mersenne mersenne( seq );

    for( size_t i = 0; i < 2000; ++i ) {
        CHECK_EQ( mersenne.get(), gen() );
    }
}

void challenge3_22() {
    {
        uint32_t seed = 26210;
        Mersenne mersenne( seed );
        Mersenne mersenne2( seed );

        for( size_t i = 0; i < 2000; ++i ) {
            CHECK_EQ( mersenne.get(), mersenne2.get() );
        }
    }

    {
        // current time
        uint32_t t = std::time( nullptr );

        // wait between 40...1000 secs
        // and initialize Mersenne with it
        uint32_t t2 = t + 40 + randomnumber::get( 1000 - 40 );
        Mersenne secret( t2 );
        uint32_t first = secret.get();

        // map first rng output to seed
        std::map<uint32_t, uint32_t> lookup;

        for( size_t i = 0; i < 1000; ++i ) {
            Mersenne mersenne( t + i );
            lookup.emplace( mersenne.get(), t + i );
        }

        CHECK_EQ( t2, lookup[first] );
    }
}

void challenge3_23() {
    uint32_t r = randomnumber::get();
    uint32_t s = Mersenne::scramble( r );
    uint32_t r2 = Mersenne::unscramble( s );
    CHECK( r != s );
    CHECK_EQ( r, r2 );
}
