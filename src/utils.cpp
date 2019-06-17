#include "utils.hpp"

#include <map>
#include <cmath>
#include <fstream>
#include <bitset>

#include "converter.hpp"
#include "crypto.hpp"
#include "log.hpp"


Bytes utils::fromBase64File( const std::string& filename ) {
    std::ifstream file( filename.c_str(), std::ios::binary | std::ios::in );

    if( !file ) { return {}; }

    std::stringstream ss;
    std::string line;

    while( std::getline( file, line ) ) {
        ss << line;
    }

    Bytes bytes = converter::base64ToBinary( ss.str( ) );
    return bytes;
}

float utils::isEnglishText( const Bytes& text ) {
    std::map<int, float> freqs;
    float penalty = 0.f;

    for( const uint8_t c : text ) {
        bool isText = c == '\n' ||
                      c == '\'' ||
                      c == ' ' ||
                      c == '\r' ||
                      std::isalpha( c );
        bool isCrap = std::iscntrl( c );

        if( isText ) {
            penalty--;

            if( std::isupper( c ) ) {
                freqs[std::tolower( c )] += 1;
            } else {
                freqs[std::tolower( c )] += 4;
            }
        }

        if( isCrap ) {
            penalty++;
        }
    }

    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    float probAP = 0.03f * freqs['\''];
    float probCR = 0.03f * freqs['\r'];
    float probLF = 0.03f * freqs['\n'];
    float prob_  = 0.19181f * freqs[' '];
    float probE  = 0.12702f * freqs['e'];
    float probT  = 0.09056f * freqs['t'];
    float probA  = 0.08167f * freqs['a'];
    float probO  = 0.07507f * freqs['o'];
    float probI  = 0.06966f * freqs['i'];
    float probN  = 0.06749f * freqs['n'];
    float probS  = 0.06327f * freqs['s'];

    return probAP + probCR + probLF + prob_ + probE + probT + probA + probO + probI + probN + probS - penalty;
}

std::vector<Bytes> utils::fromHexFile( const std::string& filename ) {
    std::vector<Bytes> rv;
    std::ifstream file( filename.c_str(), std::ios::binary | std::ios::in );

    if( !file ) { return rv; }

    std::string line;
    rv.reserve( 32 );

    while( std::getline( file, line ) ) {
        rv.emplace_back( converter::hexToBinary( line ) );
    }

    return rv;
}

std::vector<std::string> utils::fromFile( const std::string& filename ) {
    std::vector<std::string> rv;
    std::ifstream file( filename.c_str(), std::ios::binary | std::ios::in );

    if( !file ) { return rv; }

    std::string line;
    rv.reserve( 32 );

    while( std::getline( file, line ) ) {
        rv.emplace_back( line );
    }

    return rv;
}

utils::Guess utils::guessKey( const Bytes& text ) {
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

template<class Container>
size_t utils::hammingDistance( const Container& first, const Container& second ) {
    size_t size = first.size();
    size_t distance = 0;

    if( size != second.size() ) {
        LOG( "Error: first and second have different lenghts" );
        return 0;
    }

    for( size_t i = 0; i < size ; ++i ) {
        distance += std::bitset<8>( first[i] ^ second[i] ).count();
    }

    return distance;
}

template size_t utils::hammingDistance<Bytes>( const Bytes& first, const Bytes& second );
template size_t utils::hammingDistance<std::string>( const std::string& first, const std::string& second );

std::ostream& operator<<( std::ostream& os, const Bytes& bytes ) {
    os << converter::binaryToHex( bytes );
    return os;
}

std::vector<Bytes> utils::disperse( const Bytes& mono, const size_t& parts ) {
    std::vector<Bytes> many( parts );
    size_t size = mono.size();

    // performance

    for( Bytes& one : many ) {
        one.reserve( 1 + size / parts );
    }

    // split
    for( size_t i = 0; i < size; ++i ) {
        many[i % parts].push_back( mono[i] );
    }

    return many;
}


Bytes& operator+( Bytes& first, const Bytes& second ) {
    first.insert( first.end(), second.cbegin(), second.cend() );
    return first;
}

void utils::toFile( const std::string& filename, const Bytes& data ) {
    std::ofstream file( filename.c_str(), std::ios::binary | std::ios::out );

    if( !file ) {
        LOG( "Could not open " << filename << std::endl; )
        return;
    }

    file.write( reinterpret_cast<const char*>( data.data() ), data.size() );

}

float utils::shannonEntropy( const Bytes& data ) {
    std::map<uint8_t, size_t> stats ;

    for( const uint8_t c : data ) {
        ++stats[ c ];
    }

    size_t size = data.size();
    float entropy = 0 ;

    for( auto&& stat : stats ) {
        float frequency = static_cast<float>( stat.second ) / size;
        entropy -= frequency * log2f( frequency );
    }

    return entropy;
}
