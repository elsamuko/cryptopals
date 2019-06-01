#include <iostream>
#include "utils.hpp"
#include <map>
#include <cfloat>

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

// https://cryptopals.com/sets/1/challenges/3
void challenge1_3() {
    LOG( "Running challenge 1.3" );
    std::string secret = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    Bytes bytes = utils::hexToBinary( secret );

    utils::Guess guess = utils::guessKey( bytes );

    Bytes decrypted = utils::XOR( bytes, guess.key );
    std::string printable( ( const char* )decrypted.data(), decrypted.size() );
    std::string expected = "Cooking MC's like a pound of bacon";
    CHECK_EQ( printable, expected );
}

// https://cryptopals.com/sets/1/challenges/4
void challenge1_4() {
    LOG( "Running challenge 1.4" );
    std::vector<Bytes> lines = utils::fromHexFile( "1_4.txt" );

    utils::Guess best{};
    size_t bestLine = 0;

    for( size_t i = 0; i < lines.size(); ++i ) {
        utils::Guess guess = utils::guessKey( lines[i] );

        if( guess.probability > best.probability ) {
            best = guess;
            bestLine = i;
        }
    }

    Bytes decrypted = utils::XOR( lines[bestLine], best.key );
    std::string printable( ( const char* )decrypted.data(), decrypted.size() );
    std::string expected = "Now that the party is jumping\n";
    CHECK_EQ( printable, expected );
}

int main() {

    challenge1_1();
    challenge1_2();
    challenge1_3();
    challenge1_4();

    return 0;
}
