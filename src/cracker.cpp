#include "cracker.hpp"

#include "log.hpp"

cracker::Guess cracker::guessKey( const Bytes& text ) {
    float best = 0.f;
    uint8_t bestKey = 0;

    for( uint8_t key = 0; key != 255; ++key ) {
        Bytes decrypted = crypto::XOR( text, key );
        float prob = utils::isEnglishText( decrypted );

        if( prob > best ) {
            best = prob;
            bestKey = key;
        }
    }

    return {bestKey, best};
}

size_t cracker::guessBlockSize( const cracker::BlockEncryptFunc& encryptFunc ) {
    size_t blockSize = 0;
    size_t sizeNow = 0;
    size_t sizePrevious = encryptFunc( Bytes() ).size();

    for( size_t i = 0; i < 32; ++i ) {
        sizeNow = encryptFunc( Bytes( i, 'A' ) ).size();

        if( sizeNow != sizePrevious ) {
            blockSize = sizeNow - sizePrevious;
            break;
        } else {
            sizePrevious = sizeNow;
        }
    }

    if( !blockSize ) { LOG( "Failed to guess a block size" ); }

    return blockSize;
}

std::optional<crypto::Encrypted::Type> cracker::detectECBorCBC( const Bytes& encrypted ) {
    std::optional<crypto::Encrypted::Type> guess = {};

    //! \note use entropy measurement as decision maker
#if 0
    // CBC encrypted blocks (can) have a higher entropy than ECB
    float shannon = utils::shannonEntropy( encrypted );
    float threshold = 6.f; // determined by printing some entropies with known encryption

    if( shannon > threshold ) {
        guess = crypto::Encrypted::Type::CBC;
    } else {
        guess = crypto::Encrypted::Type::ECB;
    }

    //! \note use Hamming distance as decision maker
#else

    if( encrypted.size() < 3 * 16 ) {
        LOG( "Error: Too small sample size" );
        return guess;
    }

    // 2nd and 3rd block should decrypt the same with ECB -> their Hamming distance is 0
    Bytes second = Bytes( encrypted.cbegin() + 1 * 16, encrypted.cbegin() + 2 * 16 );
    Bytes third  = Bytes( encrypted.cbegin() + 2 * 16, encrypted.cbegin() + 3 * 16 );
    size_t dist = utils::hammingDistance<Bytes>( second, third );

    if( dist == 0 ) {
        guess = crypto::Encrypted::Type::ECB;
    } else {
        guess = crypto::Encrypted::Type::CBC;
    }

#endif
    return guess;
}
