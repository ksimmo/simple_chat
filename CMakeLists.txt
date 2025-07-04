cmake_minimum_required(VERSION 4.0)
project(simple_chat)

#C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

# Find SQLite3
find_package(SQLite3 REQUIRED)
message(STATUS "Using SQLite3 ${SQLITE3_VERSION}")

# Find QT6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
message(STATUS "Using Qt6 ${QT6_VERSION}")
qt_standard_project_setup()

#somehow qt include dirs are not found
include_directories(${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS} /usr/include/qt6)


set(NET_SOURCES src/net/socket.cpp
                src/net/secure_socket.cpp
                src/net/packet.cpp
                src/net/peer.cpp
                src/net/connector.cpp )

set(CRYPTO_SOURCES src/crypto/key.cpp src/crypto/utilities.cpp src/crypto/ratchet.cpp)

set(DB_SOURCES src/db/database.cpp src/db/entry.cpp)

set(SERVER_SOURCES src/server/user.cpp)

set(CLIENT_SOURCES src/client/net_worker.cpp)

# Add server executable
add_executable(server server.cpp ${NET_SOURCES} ${DB_SOURCES} ${CRYPTO_SOURCES} ${SERVER_SOURCES})

# Add client executable
add_executable(client client.cpp ${NET_SOURCES} ${DB_SOURCES}  ${CRYPTO_SOURCES} ${CLIENT_SOURCES})

qt_add_executable(test test.cpp)
target_link_libraries(test PRIVATE Qt6::Core Qt6::Widgets)

# Platform-specific settings
if(WIN32)
    target_link_libraries(server ws2_32 OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
    target_link_libraries(client ws2_32 OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
else()
    # On Unix/Linux systems, no special libraries usually needed for sockets
    target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
    target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3 Qt6::Core)
endif()

set(TESTS test/test_keygen.cpp test/test_x3hd.cpp test/test_aead.cpp test/test_ratchets.cpp)
foreach(test ${TESTS})
    get_filename_component (TName ${test} NAME_WE)
    add_executable(${TName} ${test} ${NET_SOURCES} ${DB_SOURCES} ${CRYPTO_SOURCES})
    target_link_libraries(${TName} OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
endforeach()


