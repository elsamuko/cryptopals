#include <iostream>
#include "utils.hpp"

int main() {
    // https://cryptopals.com/sets/1/challenges/1
    std::string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    std::cout << "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" << std::endl;

    std::string base64 = utils::hexToBase64( hex );
    std::cout << base64 << std::endl;

    return 0;
}
