#include "cracker.hpp"

#include "log.hpp"

cracker::GuessedKey cracker::guessKey( const Bytes& text ) {
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

cracker::GuessedSize cracker::guessBlockSize( const cracker::BlockEncryptFunc& encryptFunc ) {
    cracker::GuessedSize guess;

    size_t sizeNow = 0;
    size_t sizePrevious = encryptFunc( Bytes() ).size();
    size_t extra = sizePrevious; // max size of extra bytes

    // guess prefix + suffix size
    for( size_t i = 0; i < 32; ++i ) {
        sizeNow = encryptFunc( Bytes( i, '\0' ) ).size();

        // encryptFunc needs a new block at i bytes
        if( sizeNow != sizePrevious ) {
            guess.blockSize = sizeNow - sizePrevious;
            extra -= i;
            break;
        } else {
            sizePrevious = sizeNow;
        }
    }

    if( !guess.blockSize ) {
        LOG( "Failed to guess a block size" );
        return guess;
    }

    // assuming ECB, when two consecutive blocks are the same -> the rest is suffix only
    size_t suffixStart = 0;

    for( size_t i = 0; i < 1024; ++i ) {
        Bytes encrypted = encryptFunc( Bytes( i, '\0' ) );
        size_t blocks = encrypted.size() / guess.blockSize;

        if( blocks < 2 ) { continue; }

        for( size_t j = 0; j < blocks - 2; ++j ) {

            Bytes first( encrypted.cbegin() + ( j + 0 ) * guess.blockSize,
                         encrypted.cbegin() + ( j + 1 ) * guess.blockSize );
            Bytes second( encrypted.cbegin() + ( j + 1 ) * guess.blockSize,
                          encrypted.cbegin() + ( j + 2 ) * guess.blockSize );

            // then rest is suffix
            if( first == second ) {
                suffixStart = i;
                sizePrevious = encrypted.size();
                // max suffix size
                guess.suffix = encrypted.size() - ( j + 2 ) * guess.blockSize;
                goto next;
            }
        }
    }

next:

    // guess suffix size
    for( size_t i = suffixStart; i < suffixStart + guess.blockSize; ++i ) {
        sizeNow = encryptFunc( Bytes( i, '\0' ) ).size();

        // encryptFunc needs a new block at i bytes
        if( sizeNow != sizePrevious ) {
            guess.suffix -= ( i - suffixStart );
            break;
        } else {
            sizePrevious = sizeNow;
        }
    }

    guess.prefix = extra - guess.suffix;
    return guess;
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
