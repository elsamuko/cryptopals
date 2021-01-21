#pragma once

#include <vector>
#include <string>
#include <cstring>
#include <bitset>
#include <algorithm>
#include <stdexcept>

#include "converter.hpp"

// class to calculate with big unsigned integrals
class BigNum {
    private:
        // read RTL hex into binary
        static Bytes hexToBinary( const std::string& hex ) {
            size_t size   = hex.size() / 2;
            Bytes binary;
            binary.reserve( size );

            if( size ) {
                size_t pos = hex.size();

                while( pos > 1 ) {
                    pos -= 2;
                    uint8_t lower  = static_cast<uint8_t>( converter::parseHex( hex[pos + 1] ) );
                    uint8_t higher = static_cast<uint8_t>( converter::parseHex( hex[pos] ) );
                    binary.emplace_back( lower + 16 * higher );
                }
            }

            if( hex.size() % 2 ) {
                uint8_t lower  = static_cast<uint8_t>( converter::parseHex( hex.front() ) );
                binary.emplace_back( lower );
            }

            return binary;
        }

        static std::string binaryToHex( const Bytes& bytes ) {
            static const char table16[17] = "0123456789abcdef";

            std::string rv( 2 * bytes.size(), '\0' );
            size_t pos = bytes.size();

            while( pos ) {
                --pos;
                int a = ( bytes[pos] & 0b11110000 ) >> 4;
                int b = ( bytes[pos] & 0b00001111 );
                rv[2 * pos + 1] = table16[a];
                rv[2 * pos + 0] = table16[b];
            }

            std::reverse( rv.begin(), rv.end() );
            return rv;
        }

    public:
        static BigNum fromHex( const std::string& hex ) {
            BigNum num;
            num.places = BigNum::hexToBinary( hex );
            return num;
        }
        BigNum( const uint64_t& num = 0 ) {
            places.resize( sizeof( num ) );
            memcpy( places.data(), &num, sizeof( num ) );
        }
        friend std::ostream& operator<<( std::ostream& os, const BigNum& num );
        friend BigNum operator+( const BigNum&, const BigNum& );
        friend BigNum operator-( const BigNum&, const BigNum& );
        friend BigNum operator*( const BigNum&, const BigNum& );
        friend BigNum operator%( const BigNum&, const BigNum& );
        friend bool operator>( const BigNum&, const BigNum& );
        friend bool operator<( const BigNum&, const BigNum& );

        static BigNum mult( const BigNum& left, const BigNum& right );
        static BigNum bitshift( const BigNum& in, const int64_t& bits );
        static BigNum mod( const BigNum& base, const BigNum& modulo );
        static BigNum modpow( BigNum base, BigNum power, const BigNum& modulo );
        static BigNum add( const BigNum& left, const BigNum& right );
        static BigNum subtract( const BigNum& left, const BigNum& right ) noexcept( false );
        static bool bigger( const BigNum& left, const BigNum& right );
        static bool smaller( const BigNum& left, const BigNum& right );
        static bool equals( const BigNum& left, const BigNum& right );

        bool operator ==( const BigNum& b ) const {
            return equals( *this, b );
        }
        bool operator !=( const BigNum& b ) const {
            return !equals( *this, b );
        }

        BigNum& operator +=( const BigNum& b ) {
            *this = add( *this, b );
            return *this;
        }

        BigNum& operator *=( const BigNum& b ) {
            *this = mult( *this, b );
            return *this;
        }

        BigNum& operator %=( const BigNum& b ) {
            *this = mod( *this, b );
            return *this;
        }

        bool isNull() {
            for( const Byte& b : places ) {
                if( b != 0 ) { return false; }
            }

            return false;
        }
    private:
        Bytes places;
};

std::ostream& operator<<( std::ostream& os, const BigNum& num ) {
    os << BigNum::binaryToHex( num.places );
    return os;
}

BigNum operator+( const BigNum& left, const BigNum& right ) {
    return BigNum::add( left, right );
}

BigNum operator-( const BigNum& left, const BigNum& right ) {
    return BigNum::subtract( left, right );
}

BigNum operator*( const BigNum& left, const BigNum& right ) {
    return BigNum::mult( left, right );
}

BigNum operator%( const BigNum& left, const BigNum& right ) {
    return BigNum::mod( left, right );
}

bool operator>( const BigNum& left, const BigNum& right ) {
    return BigNum::bigger( left, right );
}

bool operator<( const BigNum& left, const BigNum& right ) {
    return BigNum::smaller( left, right );
}

BigNum BigNum::add( const BigNum& left, const BigNum& right ) {
    bool leftIsBigger = left.places.size() > right.places.size();
    BigNum res = leftIsBigger ? left : right;
    const BigNum& other = leftIsBigger ? right : left;

    Byte carry = 0;
    size_t i = 0;

    for( ; i < other.places.size(); ++i ) {
        uint16_t sum = other.places[i] + res.places[i] + carry;

        if( sum > 255 ) { carry = sum >> 8; sum %= 256; }
        else { carry = 0; }

        res.places[i] = sum;
    }

    // offset carry
    if( carry > 0 ) {
        for( ; i < res.places.size(); ++i ) {
            uint16_t sum = res.places[i] + carry;

            if( sum > 255 ) { carry = sum >> 8; sum %= 256; }
            else { carry = 0; }

            res.places[i] = sum;
        }
    }

    // push back, if there is still carry
    if( carry > 0 ) {
        res.places.emplace_back( carry );
    }

    return res;
}

//! subtracts \param right from \param left
//! throws exception if \param right is bigger than \param left
BigNum BigNum::subtract( const BigNum& left, const BigNum& right ) {

    if( right > left ) { throw std::range_error( "subtract: right > left" ); }

    BigNum res = left;
    Byte carry = 0;
    size_t i = 0;

    for( ; i < res.places.size() && i < right.places.size(); ++i ) {
        int16_t diff = res.places[i] - right.places[i] - carry;

        if( diff < 0 ) { carry = 1; diff += 256; }
        else { carry = 0; }

        res.places[i] = diff;
    }

    // offset carry
    if( carry > 0 ) {
        for( ; i < res.places.size(); ++i ) {
            int16_t diff = res.places[i] - carry;

            if( diff < 0 ) { carry = 1; diff += 256; }
            else { carry = 0; }

            res.places[i] = diff;
        }
    }

    return res;
}

bool BigNum::bigger( const BigNum& left, const BigNum& right ) {
    bool leftIsBigger = left.places.size() > right.places.size();
    const BigNum& bigger  = leftIsBigger ? left : right;
    const BigNum& smaller = leftIsBigger ? right : left;

    for( size_t i = smaller.places.size(); i < bigger.places.size(); i++ ) {
        if( bigger.places[i] != 0 ) { return leftIsBigger; }
    }

    size_t i = smaller.places.size();

    while( i-- ) {
        if( left.places[i] > right.places[i] ) { return true; }

        if( left.places[i] < right.places[i] ) { return false; }
    }

    return false;
}

bool BigNum::smaller( const BigNum& left, const BigNum& right ) {
    bool leftIsBigger = left.places.size() > right.places.size();
    const BigNum& bigger  = leftIsBigger ? left : right;
    const BigNum& smaller = leftIsBigger ? right : left;

    for( size_t i = smaller.places.size(); i < bigger.places.size(); i++ ) {
        if( bigger.places[i] != 0 ) { return !leftIsBigger; }
    }

    size_t i = smaller.places.size();

    while( i-- ) {
        if( left.places[i] < right.places[i] ) { return true; }

        if( left.places[i] > right.places[i] ) { return false; }
    }

    return false;
}

bool BigNum::equals( const BigNum& left, const BigNum& right ) {
    bool leftIsBigger = left.places.size() > right.places.size();
    const BigNum& bigger  = leftIsBigger ? left : right;
    const BigNum& smaller = leftIsBigger ? right : left;

    if( memcmp( left.places.data(), right.places.data(), smaller.places.size() ) != 0 ) { return false; }

    for( size_t i = smaller.places.size(); i < bigger.places.size(); i++ ) {
        if( bigger.places[i] != 0 ) { return false; }
    }

    return true;
}

BigNum BigNum::bitshift( const BigNum& in, const int64_t& bits ) {
    if( bits == 0 ) { return in; }

    BigNum res = in;
    int64_t offset = bits / 8;
    int64_t rest = bits % 8;

    bool oneLeft = false;

    // change negative bitshift to positive
    if( rest < 0 ) {
        oneLeft = true;
        rest += 8;
    }

    if( offset > 0 ) {
        res.places.resize( in.places.size() + offset + ( rest ? 1 : 0 ) );
    }

    // "shift" bytewise
    if( offset > 0 ) {
        std::shift_right( res.places.begin(), res.places.end(), offset );
        std::fill( res.places.begin(), res.places.begin() + offset, 0 );
    } else {
        std::shift_left( res.places.begin(), res.places.end(), -offset );
        std::fill( res.places.end() + offset, res.places.end(), 0 );
    }

    // "shift" rest bitwise
    if( !rest ) { return res; }

    static const uint8_t bottoms[] = {
        0b11111111,
        0b01111111,
        0b00111111,
        0b00011111,
        0b00001111,
        0b00000111,
        0b00000011,
        0b00000001,
    };

    static const uint8_t tops[] = {
        0b00000000,
        0b10000000,
        0b11000000,
        0b11100000,
        0b11110000,
        0b11111000,
        0b11111100,
        0b11111110,
    };

    size_t pos = res.places.size();

    Byte top = ( ( res.places[pos - 1] & tops[rest] ) >> ( 8 - rest ) );

    if( top && bits > 0 ) {
        res.places.push_back( top );
    }

    // from size-1 to 1
    while( --pos ) {
        res.places[pos] = ( ( res.places[pos] & bottoms[rest] ) << rest ) + // take lower bits and shift up
                          ( ( res.places[pos - 1] & tops[rest] ) >> ( 8 - rest ) ); // take upper bits and shift down
    }

    res.places[0] = ( res.places[0] & bottoms[rest] ) << rest; // again take lower bits and shift up

    // correct negative bitshift by one place left
    if( oneLeft ) {
        std::shift_left( res.places.begin(), res.places.end(), 1 );
        res.places.back() = in.places.back() >> ( 8 - rest );
    }

    return res;
}

BigNum BigNum::mult( const BigNum& left, const BigNum& right ) {
    BigNum res;

    size_t offset = 0;

    for( const Byte& b : right.places ) {
        std::bitset<8> bits( b );

        for( size_t i = 0; i < 8; ++i ) {
            if( bits[i] ) {
                BigNum tmp = left;
                tmp.places.resize( tmp.places.size() + offset );
                // shift by offset bits and add to res
                tmp = BigNum::bitshift( tmp, offset );
                res += tmp;
            }

            ++offset;
        }
    }

    // remove superfluous zeros
    while( res.places.size() > 8 && res.places.back() == 0 ) {
        res.places.pop_back();
    }

    return res;
}

BigNum BigNum::mod( const BigNum& base, const BigNum& modulo ) {

    if( base < modulo ) { return base; }

    if( base == modulo ) { return BigNum( 0 ); }

    BigNum sub = modulo;
    BigNum rest = base;

    int shift = 0;

    // search biggest modulo << shift, which is smaller than base
    while( sub < base ) {
        shift++;
        sub = BigNum::bitshift( modulo, shift );

        if( sub == base ) {
            return BigNum( 0 );
        }
    }

    while( shift-- ) {
        sub = BigNum::bitshift( modulo, shift );

        if( rest > sub ) {
            rest = rest - sub;
        }

        if( rest == sub ) {
            return BigNum( 0 );
        }
    }

    // remove superfluous zeros
    while( rest.places.size() > 8 && rest.places.back() == 0 ) {
        rest.places.pop_back();
    }

    return rest;
}

//def power_mod(b, e, m):
//    " Without using builtin function "
//    x = 1
//    while e > 0:
//        b, e, x = (
//            b * b % m,
//            e // 2,
//            b * x % m if e % 2 else x
//        )

//    return x

BigNum BigNum::modpow( BigNum base, BigNum power, const BigNum& modulo ) {
    BigNum x( 1 );
    BigNum null( 0 );

    while( power > null ) {
        if( power % 2 != null ) {
            x = base * x;
            x = x % modulo;
        }

        base = base * base;
        base = base % modulo;
        power = BigNum::bitshift( power, -1 );
    }

    return x;
}
