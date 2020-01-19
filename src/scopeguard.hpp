#pragma once

#include <functional>

// via http://stackoverflow.com/a/1295338
#define CONCAT_IMPL( x, y ) x##y
#define MACRO_CONCAT( x, y ) CONCAT_IMPL( x, y )
#define UNIQUE_NAME MACRO_CONCAT( uniqueScopeGuard_, __COUNTER__ )

#define ON_EXIT( A ) ScopeGuard UNIQUE_NAME( [&]{ A; } );

struct ScopeGuard {
    std::function<void()> onExit;
    ScopeGuard( const std::function<void()>& onExit ) : onExit( onExit ) {}
    ~ScopeGuard() { onExit(); }
};
