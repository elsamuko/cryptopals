#include "set5.hpp"

#include "random.hpp"
#include "utils.hpp"

void challenge5_33() {
    int p = 37;
    int g = 5;

    int a = randomnumber::get() % 37;
    int A = ( int )std::pow( g, a ) % p;

    int b = randomnumber::get() % 37;
    int B = ( int )std::pow( g, b ) % p;

    int s = ( int )std::pow( B, a ) % p;
    int s2 = ( int )std::pow( A, b ) % p;

    CHECK_EQ( s, s2 );

    CHECK_EQ( BigNum( 2 ) + BigNum( 3 ), BigNum( 5 ) );
    CHECK_EQ( BigNum::fromHex( "ff" ) + BigNum::fromHex( "1" ), BigNum::fromHex( "0001" ) );
    CHECK_EQ( BigNum::fromHex( "f" ) + BigNum( 1 ), BigNum::fromHex( "1000" ) );

    CHECK_EQ( BigNum( 2 ) * BigNum( 8 ), BigNum( 16 ) );
    CHECK_EQ( BigNum( 333 ) * BigNum( 6 ), BigNum( 1998 ) );
    CHECK_EQ( BigNum( 333 ) * BigNum( 333 ), BigNum( 110889 ) );

    CHECK( BigNum( 333 ) > BigNum( 1 ) );
    CHECK( BigNum::fromHex( "121" ) > BigNum::fromHex( "12" ) );
    CHECK( BigNum::fromHex( "123" ) > BigNum::fromHex( "122" ) );
}
