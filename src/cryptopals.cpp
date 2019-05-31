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

// https://cryptopals.com/sets/1/challenges/2
void challenge1_2() {
    LOG( "Running challenge 1.2" );
    std::string first = "1c0111001f010100061a024b53535009181c";
    std::string second = "686974207468652062756c6c277320657965";
    std::string expected = "746865206b696420646f6e277420706c6179";
    std::string calculated = utils::XOR( first, second );
    CHECK_EQ( expected, calculated );
}

int main() {

    challenge1_1();
    challenge1_2();

    return 0;
}
