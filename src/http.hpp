#pragma once

#include <string>

namespace http {
// returns the http status for a GET request on localhost:9000
int GET( const std::string& url );
}
