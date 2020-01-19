#include "http.hpp"

#include <netinet/ip.h>
#include <unistd.h>

#include "scopeguard.hpp"
#include "log.hpp"

// from
// boost/endian/detail/endian_reverse.hpp
inline uint16_t endian_reverse( uint16_t x ) {
    return ( x << 8 ) | ( x >> 8 );
}

#define CHECK_RC( A ) if( ( A ) < 0 ) { LOG( "[FAILURE] : "#A ); break; }

int http::GET( const std::string& url ) {
    int status = 0;

    do {
        int sockfd = socket( AF_INET, SOCK_STREAM, 0 );
        CHECK_RC( sockfd );
        ON_EXIT( close( sockfd ) );

        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = endian_reverse( 9000 );
        server.sin_addr.s_addr = 0x100007f; // 127.0.0.1

        CHECK_RC( connect( sockfd, ( struct sockaddr* )&server, sizeof( server ) ) );
        ON_EXIT( shutdown( sockfd, SHUT_RDWR ) );

        // http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
        std::string domain = "http://localhost:9000";
        std::string path = url.substr( domain.size() );
        std::string request = "GET " + path + " HTTP/1.1\r\n\r\n";
        CHECK_RC( write( sockfd, request.data(), request.size() ) );

        std::string response( 1000, '\0' );
        CHECK_RC( read( sockfd, response.data(), response.size() ) );

        if( response.find( "HTTP/1.1 200 OK" ) != std::string::npos ) {
            status = 200;
        }

        if( response.find( "HTTP/1.1 500 Internal Server Error" ) != std::string::npos ) {
            status = 500;
        }
    } while( false );


    return status;
}
