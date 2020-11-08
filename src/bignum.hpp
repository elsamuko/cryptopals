#pragma once

#include <vector>
#include <string>
#include <cstring>
#include <bitset>
#include <algorithm>
#include <stdexcept>

#include <converter.hpp>

// class to calculate with big unsigned integrals
class BigNum {
    public:
        static BigNum fromHex( const std::string& hex ) {
            BigNum num;
            num.places = converter::hexToBinary( hex );
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
        static BigNum bitshift( const BigNum& in, const size_t& bits );
        static BigNum mod( const BigNum& base, const BigNum& modulo );
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
    os << converter::binaryToHex( num.places );
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

BigNum BigNum::bitshift( const BigNum& in, const size_t& bits ) {
    BigNum res = in;
    size_t offset = bits / 8;
    size_t rest = bits % 8;
    res.places.resize( in.places.size() + offset + ( rest ? 1 : 0 ) );

    // "shift" bytewise
    std::rotate( res.places.rbegin(), res.places.rbegin() + offset, res.places.rend() );

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

    // from size-1 to 1
    while( --pos ) {
        res.places[pos] = ( ( res.places[pos] & bottoms[rest] ) << rest ) + // take lower bits and shift up
                          ( ( res.places[pos - 1] & tops[rest] ) >> ( 8 - rest ) ); // take upper bits and shift down
    }

    res.places[0] = ( res.places[0] & bottoms[rest] ) << rest; // again take lower bits and shift up

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

    return res;
}

BigNum BigNum::mod( const BigNum& base, const BigNum& modulo ) {

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

BigNum modpow( const BigNum& base, const BigNum& power, const BigNum& modulo ) {
    BigNum  result;


    return base;
}
