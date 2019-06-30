#include "cracker.hpp"

#include "crypto.hpp"
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
