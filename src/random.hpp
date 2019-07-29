#pragma once

#ifndef _WIN32
#include <sys/random.h>
#else
#include <Windows.h>
#endif

#include "types.hpp"
#include "log.hpp"

namespace randombuffer {

Bytes get( const size_t& size ) {
    // uninitialized buffer
    Bytes buffer( size );

#if __APPLE__
    bool rv = 0 == getentropy( buffer.data(), buffer.size() );
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
