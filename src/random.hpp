#pragma once

#ifdef _WIN32
#include <Windows.h>
#elif __APPLE__
#include <Security/Security.h>
#elif __linux__
#include <sys/random.h>
#endif
#include <cstdlib>
#include <ctime>
#include <random>

#include "types.hpp"
#include "log.hpp"

namespace randombuffer {

inline Bytes get( const size_t& size ) {
    // uninitialized buffer
    Bytes buffer( size );

#if __APPLE__
    bool rv = 0 == SecRandomCopyBytes( kSecRandomDefault, buffer.size(), buffer.data() );
#elif _WIN32
    bool rv = 0 == ::BCryptGenRandom( nullptr, buffer.data(), buffer.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG );
#elif __linux__
    bool rv = size == getrandom( buffer.data(), buffer.size(), 0 );
#endif

    if( !rv ) {
        LOG( "Error: getrandom returned " << rv );
        return {};
    }

    return buffer;
}

}

namespace randomnumber {

inline int get( const int max ) {
    std::random_device rd;
    std::uniform_int_distribution<int> d( 0, max - 1 );
    return d( rd );
}

}
