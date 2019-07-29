#pragma once

#include <sys/random.h>

#include "types.hpp"
#include "log.hpp"

namespace randombuffer {

Bytes get( const size_t& size ) {
    // uninitialized buffer
    Bytes buffer( size );

#if __APPLE__
    bool rv = 0 == getentropy( buffer.data(), buffer.size() );
#elif _WIN32
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
