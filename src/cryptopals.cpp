#include "set1.hpp"
#include "set2.hpp"

#include <map>
#include <functional>

#include "log.hpp"

int main( int argc, char* argv[] ) {

    const std::map<std::string, std::function<void()>> challenges = {

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

    };

    // run one challenge
    if( argc == 2 ) {
        auto it = challenges.find( argv[1] );

        if( it != challenges.cend() ) {
            it->second();
        } else {
            LOG( argv[1] << " not found" );
        }
    }
    // run all challenges
    else {
        for( auto&& it : challenges ) {
            it.second();
        }
    }

    return 0;
}
