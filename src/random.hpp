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
#include <cstring>
#include <random>
#include <array>

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

inline uint32_t get( const uint32_t max = -1 ) {
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> d( 0, max - 1 );
    return d( rd );
}

}

// https://de.wikipedia.org/wiki/Mersenne-Twister#Algorithmus
class Mersenne {
    public:
        static const size_t size = 624;
        static const size_t twopow31 = 2147483648;
        static const size_t twopow11 = 2048;
        static const size_t twopow7 = 128;
        static const size_t twopow15 = 32768;
        static const size_t twopow18 = 262144;
        using Init = std::array<uint32_t, size>;
        using State = std::array<uint32_t, 2 * size>;

        explicit Mersenne( const Init& init ) {
            std::memcpy( state.data(), init.data(), size * sizeof( uint32_t ) );
        }
        explicit Mersenne( std::seed_seq& seq ) {
            Mersenne::Init init;
            seq.generate( init.begin(), init.end() );
            std::memcpy( state.data(), init.data(), size * sizeof( uint32_t ) );
        }
        explicit Mersenne( const uint32_t& seed ) {
            std::seed_seq seq{ seed };
            Mersenne::Init init;
            seq.generate( init.begin(), init.end() );
            std::memcpy( state.data(), init.data(), size * sizeof( uint32_t ) );
        }

        uint32_t get() {
            if( pos == size ) {
                shuffle();
                pos = 0;
            }

            uint32_t v = state[pos];
            pos++;
            return scramble( v );
        }

        // spread result for equal bits distribution
        static uint32_t scramble( uint32_t a ) {
            a ^= ( a >> 11 );
            a ^= ( ( a << 7 ) & 0x9D2C5680 );
            a ^= ( ( a << 15 ) & 0xEFC60000 );
            a ^= ( a >> 18 );
            return a;
        }

        // unspread result to calc internal state
        static uint32_t unscramble( uint32_t a ) {
            // 1.
            {
                a ^= ( a >> 18 );
            }

            // 2.
            {
                a ^= ( ( a << 15 ) & 0xEFC60000 );
            }

            // 3.
            {
                uint32_t filter1 = 0b00000000000000000000000001111111;
                uint32_t filter2 = 0b00000000000000000011111110000000;
                uint32_t filter3 = 0b00000000000111111100000000000000;
                uint32_t filter4 = 0b00001111111000000000000000000000;
                uint32_t filter5 = 0b11110000000000000000000000000000;

                uint32_t a1 = a & filter1;
                uint32_t a2 = ( a ^ ( ( a1 << 7 ) & 0x9D2C5680 ) ) & filter2;
                uint32_t a3 = ( a ^ ( ( a2 << 7 ) & 0x9D2C5680 ) ) & filter3;
                uint32_t a4 = ( a ^ ( ( a3 << 7 ) & 0x9D2C5680 ) ) & filter4;
                uint32_t a5 = ( a ^ ( ( a4 << 7 ) & 0x9D2C5680 ) ) & filter5;

                a = a5 | a4 | a3 | a2 | a1;
            }

            // 4.
            {
                uint32_t filter1 = 0b11111111111000000000000000000000;
                uint32_t filter2 = 0b00000000000111111111110000000000;
                uint32_t filter3 = 0b00000000000000000000001111111111;

                uint32_t a1 = a & filter1;
                uint32_t a2 = ( ( a1 >> 11 ) ^ a ) & filter2;
                uint32_t a3 = ( ( a2 >> 11 ) ^ a ) & filter3;

                a = a1 | a2 | a3;
            }

            return a;
        }
    private:

        // generate new state of 624 numbers
        void shuffle() {

            for( size_t i = 0; i < size; ++i ) {
                uint32_t h = state[i] - state[i] % twopow31 + state[i + 1] % twopow31;
                state[i + size] = state[i + size - 227] ^ h / 2 ^ ( ( h % 2 ) * 0x9908b0df );
            }

            std::memcpy( &state[0], &state[size], size * sizeof( uint32_t ) );
        }
    private:
        size_t pos = size;
        State state;
};
