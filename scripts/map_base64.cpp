#!/usr/bin/env cppsh
#include <iostream>
#include <iomanip>

int main() {
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int i = 0;
    std::cout << "{" << std::endl;

    for( const char c : chars ) {
        std::cout << " { '" << c << "', ";
        std::cout.width( 2 );
        std::cout << i << " },";
        ++i;

        if( ( i % 8 ) == 0 ) { std::cout << std::endl; }
    }

    std::cout << "}" << std::endl;

    return 0;
}
