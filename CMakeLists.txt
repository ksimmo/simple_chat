cmake_minimum_required(VERSION 4.0)
project(simple_chat)

#C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION} ${OPENSSL_INCLUDE_DIRS}")

# Find SQLite3
find_package(SQLite3 REQUIRED)
message(STATUS "Using SQLite3 ${SQLITE3_VERSION}")

# Find QT6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
#qt_standard_project_setup()

include_directories(${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})

# Add server executable
add_executable(server server.cpp src/net/socket.cpp src/net/secure_socket.cpp src/net/host.cpp src/net/packet.cpp)

# Add client executable
add_executable(client client.cpp src/net/socket.cpp src/net/secure_socket.cpp src/net/client.cpp src/net/packet.cpp)

# Platform-specific settings
if(WIN32)
    target_link_libraries(server ws2_32 OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
    target_link_libraries(client ws2_32 OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
else()
    # On Unix/Linux systems, no special libraries usually needed for sockets
    target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
    target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
endif()

