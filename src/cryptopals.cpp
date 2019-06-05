#include <iostream>
#include "utils.hpp"
#include <map>
#include <cmath>
#include <limits>
#include <future>

#include "openssl/crypto.h"

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

    // run calculations async
    std::vector<std::future<utils::Guess>> guesses;
    guesses.reserve( lines.size() );

    for( size_t i = 0; i < lines.size(); ++i ) {
        Bytes line = lines[i];
        guesses.emplace_back( std::async( std::launch::async, [line] {
            utils::Guess guess = utils::guessKey( line );
            return guess;
        } ) );
    }

    // then find best guess
    utils::Guess best{};
    size_t bestLine = 0;

    for( size_t i = 0; i < guesses.size(); ++i ) {
        utils::Guess guess = guesses[i].get();

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

void challenge1_5() {
    LOG( "Running challenge 1.5" );
    std::string plain = "Burning 'em, if you ain't quick and nimble\n"
                        "I go crazy when I hear a cymbal";
    Bytes key = {'I', 'C', 'E' };
    Bytes plainBytes( plain.cbegin(), plain.cend() );
    Bytes encrypted = utils::XOR( plainBytes, key );
    std::string hex = utils::binaryToHex( encrypted );
    std::string expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                           "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    CHECK_EQ( hex, expected );
}

void challenge1_6() {
    LOG( "Running challenge 1.6" );

    std::string test  = "this is a test";
    std::string wokka = "wokka wokka!!!";
    size_t dist = utils::hammingDistance<std::string>( test, wokka );
    CHECK_EQ( dist, 37 );

    // echo -n Hase | base64
    Bytes hase = utils::base64ToBinary( "SGFzZQ==" );
    CHECK_EQ( hase, Bytes( {'H', 'a', 's', 'e' } ) );

    Bytes text = utils::fromBase64File( "1_6.txt" );

    size_t keySize = 0;
    float bestNormalized = std::numeric_limits<float>::max();

    // approximated by 'knowing' the keysize after decryption with every keysize
    // e.g. the Millikan way of science ;) (https://hsm.stackexchange.com/a/2759)
    float normFactor = 1.20f;

    for( int i = 2; i < 40; ++i ) {
        Bytes first  = Bytes( text.cbegin() + 0 * i, text.cbegin() + 1 * i );
        Bytes second = Bytes( text.cbegin() + 1 * i, text.cbegin() + 2 * i );
        Bytes third  = Bytes( text.cbegin() + 2 * i, text.cbegin() + 3 * i );
        Bytes fourth = Bytes( text.cbegin() + 3 * i, text.cbegin() + 4 * i );

        size_t hamming1 = utils::hammingDistance<Bytes>( first, second );
        size_t hamming2 = utils::hammingDistance<Bytes>( second, third );
        size_t hamming3 = utils::hammingDistance<Bytes>( third, fourth );

        float normalized = ( float )( hamming1 + hamming2 + hamming3 ) / std::pow( i, normFactor );

        // ./cryptopals 2> >( gnuplot -p -e 'plot "/dev/stdin"' )
        // std::cerr << i << " " << normalized << std::endl;

        if( normalized < bestNormalized ) {
            bestNormalized = normalized;
            keySize = i;
        }
    }

    LOG( "Keysize is probably " << keySize );

    Bytes key;
    key.reserve( keySize );
    std::vector<Bytes> many = utils::disperse( text, keySize );

    for( const Bytes& one : many ) {
        key.push_back( utils::guessKey( one ).key );
    }

    Bytes decrypted = utils::XOR( text, key );

    std::string expected = "I'm back and I'm ringin' the bell \n"
                           "A rockin' on the mike while the fly girls yell \n"
                           "In ecstasy in the back of me \n"
                           "Well that's my DJ Deshay cuttin' all them Z's \n"
                           "Hittin' hard and the girlies goin' crazy \n"
                           "Vanilla's on the mike, man I'm not lazy. \n";
    std::string printable( ( const char* )decrypted.data(), expected.size() );

    CHECK_EQ( printable, expected );
}

void challenge1_7() {
    LOG( "Running challenge 1.7" );
    std::string opensslVersion = OpenSSL_version( OPENSSL_VERSION );
    CHECK_EQ( "OpenSSL 1.1.1c  28 May 2019", opensslVersion );
}

int main() {

    challenge1_1();
    challenge1_2();
    challenge1_3();
    challenge1_4();
    challenge1_5();
    challenge1_6();
    challenge1_7();

    return 0;
}
