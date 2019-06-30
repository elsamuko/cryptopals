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

std::optional<crypto::Encrypted::Type> cracker::detectECBorCBC( const Bytes& encrypted, const size_t& blockSize ) {
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

    if( encrypted.size() < 3 * blockSize ) {
        LOG( "Error: Too small sample size" );
        return guess;
    }

    size_t blockcount = encrypted.size() / blockSize;
    size_t center = blockcount / 2;

    size_t from1 = ( center - 1 ) * blockSize;
    size_t to1 = ( center ) * blockSize;
    size_t from2 = to1;
    size_t to2 = ( center + 1 ) * blockSize;
    Bytes::const_iterator start = encrypted.cbegin();

    // center blocks should decrypt the same with ECB -> their Hamming distance is 0
    Bytes centerLeft  = Bytes( start + from1, start + to1 );
    Bytes centerRight = Bytes( start + from2, start + to2 );
    size_t dist = utils::hammingDistance<Bytes>( centerLeft, centerRight );

    if( dist == 0 ) {
        guess = crypto::Encrypted::Type::ECB;
    } else {
        guess = crypto::Encrypted::Type::CBC;
    }

#endif
    return guess;
}
