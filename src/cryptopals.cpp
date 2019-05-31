#include <iostream>
#include "utils.hpp"

// https://cryptopals.com/sets/1/challenges/1
void challenge1_1() {
    LOG( "Running challenge 1.1" );
    std::string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    std::string expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    std::string calculated = utils::hexToBase64( hex );
    CHECK_EQ( expected, calculated );
}

int main() {

    challenge1_1();

    return 0;
}
