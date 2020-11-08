#include "set5.hpp"

#include "random.hpp"
#include "utils.hpp"
#include "bignum.hpp"

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

    BigNum pBig = BigNum::fromHex( "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                                   "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                                   "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                                   "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                                   "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                                   "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                                   "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                                   "fffffffffffff" );
    BigNum gBig( 2 );

    CHECK_EQ( BigNum( 2 ) + BigNum( 3 ), BigNum( 5 ) );
    CHECK_EQ( BigNum::fromHex( "ff" ) + BigNum::fromHex( "1" ), BigNum::fromHex( "0001" ) );
    CHECK_EQ( BigNum::fromHex( "f" ) + BigNum( 1 ), BigNum::fromHex( "1000" ) );

    CHECK_EQ( BigNum( 5 ) - BigNum( 3 ), BigNum( 2 ) );
    CHECK_EQ( BigNum::fromHex( "0001" ) - BigNum::fromHex( "1" ), BigNum::fromHex( "ff" ) );
    CHECK_EQ( BigNum::fromHex( "1000" ) - BigNum( 1 ), BigNum::fromHex( "f" ) );

    CHECK_EQ( BigNum( 2 ) * BigNum( 8 ), BigNum( 16 ) );
    CHECK_EQ( BigNum( 333 ) * BigNum( 6 ), BigNum( 1998 ) );
    CHECK_EQ( BigNum( 333 ) * BigNum( 333 ), BigNum( 110889 ) );

    CHECK( BigNum( 333 ) > BigNum( 1 ) );
    CHECK( BigNum::fromHex( "121" ) > BigNum::fromHex( "12" ) );
    CHECK( BigNum::fromHex( "123" ) > BigNum::fromHex( "122" ) );

    CHECK( BigNum( 1 ) < BigNum( 333 ) );
    CHECK( BigNum::fromHex( "12" ) < BigNum::fromHex( "121" ) );
    CHECK( BigNum::fromHex( "122" ) < BigNum::fromHex( "123" ) );
    CHECK( BigNum( 123 ) < BigNum( 123456789 ) );

    CHECK_EQ( BigNum( 8 ) % BigNum( 5 ), BigNum( 3 ) );
    CHECK_EQ( BigNum( 123456789 ) % BigNum( 123 ), BigNum( 90 ) );
}
