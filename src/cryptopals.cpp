#include "set1.hpp"
#include "set2.hpp"
#include "set3.hpp"

#include <vector>
#include <functional>
#include <algorithm>

#include "log.hpp"

int main( int argc, char* argv[] ) {

    const std::vector<std::pair<std::string, std::function<void()>>> challenges = {

        // https://cryptopals.com/sets/1
        { "1.1", challenge1_1 },
        { "1.2", challenge1_2 },
        { "1.3", challenge1_3 },
        { "1.4", challenge1_4 },
        { "1.5", challenge1_5 },
        { "1.6", challenge1_6 },
        { "1.7", challenge1_7 },
        { "1.8", challenge1_8 },

        // https://cryptopals.com/sets/2
        { "2.9", challenge2_9 },
        { "2.10", challenge2_10 },
        { "2.11", challenge2_11 },
        { "2.12", challenge2_12 },
        { "2.13", challenge2_13 },
        { "2.14", challenge2_14 },
        { "2.15", challenge2_15 },
        { "2.16", challenge2_16 },

        // https://cryptopals.com/sets/3
        { "3.17", challenge3_17 },
    };

    // run one challenge
    if( argc > 1 ) {

        for( int arg = 1; arg < argc; ++arg ) {
            auto it = std::find_if( challenges.cbegin(), challenges.cend(), [argv, arg]( const auto & pair ) {
                return pair.first == std::string( argv[arg] );
            } );

            if( it != challenges.cend() ) {
                LOG( "Running challenge " << it->first );
                it->second();
            } else {
                LOG( argv[arg] << " not found" );
            }
        }

    }
    // run all challenges
    else {
        for( auto&& it : challenges ) {
            LOG( "Running challenge " << it.first );
            it.second();
        }
    }

    return 0;
}
