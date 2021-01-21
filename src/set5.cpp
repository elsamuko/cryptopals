#include "set5.hpp"

#include "random.hpp"
#include "utils.hpp"
#include "bignum.hpp"

void challenge5_33() {
    {
        int p = 37;
        int g = 5;

        int a = randomnumber::get() % 37;
        int A = ( int )std::pow( g, a ) % p;

        int b = randomnumber::get() % 37;
        int B = ( int )std::pow( g, b ) % p;

        int s = ( int )std::pow( B, a ) % p;
        int s2 = ( int )std::pow( A, b ) % p;

        CHECK_EQ( s, s2 );
    }

    {
        //        BigNum pBig = BigNum::fromHex( "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        //                                       "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        //                                       "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        //                                       "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        //                                       "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        //                                       "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        //                                       "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        //                                       "fffffffffffff" );
        //        BigNum gBig( 2 );

        CHECK_EQ( BigNum::fromHex( "0001" ), BigNum( 1 ) );
        CHECK_EQ( BigNum::fromHex( "100" ), BigNum( 256 ) );
        CHECK_EQ( BigNum::fromHex( "f0f" ), BigNum( 3855 ) );
        CHECK_EQ( BigNum( 2 ) + BigNum( 3 ), BigNum( 5 ) );

        CHECK_EQ( BigNum( 2 ) + BigNum( 3 ), BigNum( 5 ) );
        CHECK_EQ( BigNum::fromHex( "ff" ) + BigNum::fromHex( "1" ), BigNum::fromHex( "100" ) );
        CHECK_EQ( BigNum::fromHex( "f" ) + BigNum( 1 ), BigNum::fromHex( "10" ) );

        CHECK_EQ( BigNum( 5 ) - BigNum( 3 ), BigNum( 2 ) );
        CHECK_EQ( BigNum::fromHex( "0001" ) - BigNum::fromHex( "1" ), BigNum::fromHex( "0" ) );
        CHECK_EQ( BigNum::fromHex( "1000" ) - BigNum( 1 ), BigNum::fromHex( "fff" ) );
        CHECK_EQ( BigNum::fromHex( "eab2bc086e46208434d7c9ea583c6f319b9" ) - BigNum::fromHex( "b194f8e1ae525fd5dcfab0800000000000" ),
                  BigNum::fromHex( "df996c7a5360fa86d7081ee2583c6f319b9" ) );

        CHECK_EQ( BigNum::bitshift( BigNum( 2 ), 10 ), BigNum( 2048 ) );
        CHECK_EQ( BigNum::bitshift( BigNum( 4 ), -1 ), BigNum( 2 ) );
        CHECK_EQ( BigNum::bitshift( BigNum( 3000 ), -8 ), BigNum( 11 ) );

        // python -c "print('%x' % (int('1d6329f1c35ca4bfabb9f5610000000000',16)<<7))"
        CHECK_EQ( BigNum::bitshift( BigNum::fromHex( "1d6329f1c35ca4bfabb9f5610000000000" ), 7 ), BigNum::fromHex( "eb194f8e1ae525fd5dcfab0800000000000" ) );

        // python -c "print('%x' % (2351399303373464486466122544523690094744975233415544072992656881240319//2))"
        CHECK_EQ( BigNum::bitshift( BigNum::fromHex( "5737df12ecacc95ff94e28463b3cd1de0c674cb5d079bd3f4c037e48ff" ), -1 ), BigNum::fromHex( "2b9bef89765664affca714231d9e68ef0633a65ae83cde9fa601bf247f" ) );
        // python -c "print('%x' % (2351399303373464486466122544523690094744975233415544072992656881240319*2))"
        CHECK_EQ( BigNum::bitshift( BigNum::fromHex( "5737df12ecacc95ff94e28463b3cd1de0c674cb5d079bd3f4c037e48ff" ), 1 ), BigNum::fromHex( "ae6fbe25d95992bff29c508c7679a3bc18ce996ba0f37a7e9806fc91fe" ) );

        CHECK_EQ( BigNum( 2 ) * BigNum( 8 ), BigNum( 16 ) );
        CHECK_EQ( BigNum( 333 ) * BigNum( 6 ), BigNum( 1998 ) );
        CHECK_EQ( BigNum( 333 ) * BigNum( 333 ), BigNum( 110889 ) );

        // print('%x' % 2988348162058574136915891421498819466320163312926952423791023078876139**2)
        BigNum big = BigNum::fromHex( "6ed80fface4df443c2e9a56155272b9004e01f5dabe5f2181a603da3eb" );
        BigNum bigPow2 = BigNum::fromHex( "2ffe641681867b5b26fc4670b2aa49d14e621ddc6c4fe1430ca398100669898792541bcbeef603422d1be9910e5b12acea8195bba583c6f319b9" );
        CHECK_EQ( big * big, bigPow2 );

        CHECK( BigNum( 333 ) > BigNum( 1 ) );
        CHECK( BigNum::fromHex( "121" ) > BigNum::fromHex( "12" ) );
        CHECK( BigNum::fromHex( "123" ) > BigNum::fromHex( "122" ) );

        CHECK( BigNum( 1 ) < BigNum( 333 ) );
        CHECK( BigNum::fromHex( "12" ) < BigNum::fromHex( "121" ) );
        CHECK( BigNum::fromHex( "122" ) < BigNum::fromHex( "123" ) );
        CHECK( BigNum( 123 ) < BigNum( 123456789 ) );

        // print('%x' % ((2988348162058574136915891421498819466320163312926952423791023078876139**2)%(10**40)))
        BigNum modulo = BigNum::fromHex( "1d6329f1c35ca4bfabb9f5610000000000" );
        CHECK_EQ( bigPow2 % modulo, BigNum::fromHex( "16f9f196f96c4d2d1c3be38683c6f319b9" ) );

        CHECK_EQ( BigNum( 10 ) % BigNum( 2 ), BigNum( 0 ) );
        CHECK_EQ( BigNum( 8 ) % BigNum( 5 ), BigNum( 3 ) );
        CHECK_EQ( BigNum( 123456789 ) % BigNum( 123 ), BigNum( 90 ) );
        CHECK_EQ( BigNum( 2 ) % BigNum( 2 ), BigNum( 0 ) );

        // python -c "print(pow(2, 10, 100))"
        CHECK_EQ( BigNum::modpow( 2, 10, 100 ), BigNum( 24 ) );
        CHECK_EQ( BigNum::modpow( 2, 11, 111 ), BigNum( 50 ) );

        // https://rosettacode.org/wiki/Modular_exponentiation#Python
        // python3 -c "print('%x' % 2988348162058574136915891421498819466320163312926952423791023078876139)"
        BigNum a = BigNum::fromHex( "6ed80fface4df443c2e9a56155272b9004e01f5dabe5f2181a603da3eb" );

        // python3 -c "print('%x' % 2351399303373464486466122544523690094744975233415544072992656881240319)"
        BigNum b = BigNum::fromHex( "5737df12ecacc95ff94e28463b3cd1de0c674cb5d079bd3f4c037e48ff" );

        // python3 -c "print('%x' % 10**40)"
        BigNum m = BigNum::fromHex( "1d6329f1c35ca4bfabb9f5610000000000" ); // 10^40

        // python3 -c "print('%x' % 1527229998585248450016808958343740453059)"
        BigNum mp = BigNum::fromHex( "47cf5cc72a26166f482742959483cf0c3" );
        CHECK_EQ( BigNum::modpow( a, b, m ), mp );
    }
}
