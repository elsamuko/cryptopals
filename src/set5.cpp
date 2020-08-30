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
}
