#include "utils.hpp"

#include <map>
#include <cmath>
#include <fstream>
#include <bitset>
#include <algorithm>

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


Bytes operator+( const Bytes& first, const Bytes& second ) {
    Bytes merged = first;
    merged.insert( merged.end(), second.cbegin(), second.cend() );
    return merged;
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

template<char separator>
std::map<std::string, std::string> tokenizeAndSplit( const std::string& params ) {

    std::map<std::string, std::string> parsed;
    std::vector<std::string> items;

    std::string::const_iterator start = params.cbegin();
    std::string::const_iterator end   = params.cend();
    size_t from = 0;
    size_t to = 0;

    // tokenize by separator
    while( ( to = params.find( separator, from ) ) != std::string::npos ) {
        if( ( start + from ) != ( start + to ) ) {
            items.emplace_back( start + from, start + to );
        }

        from = to + 1;
    }

    // last token, if not empty
    if( ( start + from ) != end ) {
        items.emplace_back( start + from, end );
    }

    // split tokens by '='
    for( auto&& item : items ) {
        size_t pos = item.find( '=' );

        if( pos == 0 ) { continue; }

        if( pos != std::string::npos ) {
            parsed.emplace( item.substr( 0, pos ), item.substr( pos +  1 ) );
        } else {
            parsed.emplace( item, "" );
        }
    }

    return parsed;
}

std::map<std::string, std::string> utils::parseGETParams( const std::string& params ) {
    return tokenizeAndSplit<'&'>( params );
}

template<class A, class B>
std::ostream& operator<<( std::ostream& os, const std::map<A, B>& map ) {
    os << "{" ;

    for( auto&& it : map ) {
        os << "{" << it.first << ", " << it.second << "}";
    }

    os << "}" ;

    return os;
}

template std::ostream& operator<<( std::ostream& os, const std::map<std::string, std::string>& map );

std::string utils::profileFor( const std::string& mail ) {
    std::string copy = mail;

    // remove '&' and '='
    // https://en.wikipedia.org/wiki/Erase%E2%80%93remove_idiom
    copy.erase( std::remove( copy.begin(), copy.end(), '=' ), copy.end() );
    copy.erase( std::remove( copy.begin(), copy.end(), '&' ), copy.end() );

    // assemble request
    std::stringstream request;
    request << "email=" << copy << "&uid=10&role=user";
    return request.str();
}

std::string utils::generateGETRequest( const std::string& userdata ) {
    std::string copy = userdata;

    // remove ';' and '='
    // https://en.wikipedia.org/wiki/Erase%E2%80%93remove_idiom
    copy.erase( std::remove( copy.begin(), copy.end(), ';' ), copy.end() );
    copy.erase( std::remove( copy.begin(), copy.end(), '=' ), copy.end() );

    // assemble request
    std::stringstream request;
    request << "comment1=cooking%20MCs;userdata=" << copy << ";comment2=%20like%20a%20pound%20of%20bacon";
    return request.str();
}

bool utils::isAdmin( const std::string& params ) {
    std::map<std::string, std::string> pairs = tokenizeAndSplit<';'>( params );
    return pairs["admin"] == "true";
}
