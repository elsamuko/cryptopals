#pragma once

#include <sys/random.h>

#include "types.hpp"
#include "log.hpp"

namespace randombuffer {

Bytes get( const size_t& size ) {
    // uninitialized buffer
    Bytes buffer( size );

    ssize_t rv = getrandom( buffer.data(), buffer.size(), 0 );

    if( rv != size ) {
        LOG( "Error: getrandom returned " << rv );
        return {};
    }

    return buffer;
}

}
