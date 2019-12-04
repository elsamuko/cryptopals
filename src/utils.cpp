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
                freqs[std::tolower( c )] += 2;
            }
        }

        if( isCrap ) {
            penalty++;
        }
    }

    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    float props = 0.f;
    props += 0.03f * freqs['\''];
    props += 0.03f * freqs['\r'];
    props += 0.03f * freqs['\n'];
    props += 0.19181f * freqs[' '];
    props += 0.12702f * freqs['e'];
    props += 0.09056f * freqs['t'];
    props += 0.08167f * freqs['a'];
    props += 0.07507f * freqs['o'];
    props += 0.06966f * freqs['i'];
    props += 0.06749f * freqs['n'];
    props += 0.06327f * freqs['s'];
    props += 0.06094f * freqs['h'];
    props += 0.05987f * freqs['r'];
    props += 0.04253f * freqs['d'];
    props += 0.04025f * freqs['l'];
    props += 0.02782f * freqs['c'];
    props += 0.02758f * freqs['u'];
    props += 0.02406f * freqs['m'];
    props += 0.02360f * freqs['w'];
    props += 0.02228f * freqs['f'];
    props += 0.02015f * freqs['g'];
    props += 0.01974f * freqs['y'];
    props += 0.01929f * freqs['p'];
    props += 0.01492f * freqs['b'];
    props += 0.00978f * freqs['v'];
    props += 0.00772f * freqs['k'];
    props += 0.00153f * freqs['j'];
    props += 0.00150f * freqs['x'];
    props += 0.00095f * freqs['q'];
    props += 0.00074f * freqs['z'];

    return props - penalty;
}
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
    int count = 0;

    for( const uint8_t& byte : bytes ) {
        os.width( 3 );
        os << ( size_t )byte;
        os << "|";

        if( ++count % crypto::blockSize == 0 ) {
            os << "\n";
        }
    }

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

void utils::logBlock( const std::string& in ) {
    size_t size = in.size();
    std::stringstream out;

    for( size_t i = 0; i < size; i += crypto::blockSize ) {
        out << in.substr( i, crypto::blockSize ) << std::endl;
    }

    LOG( out.str() );
}
