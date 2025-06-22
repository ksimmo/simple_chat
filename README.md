# Simple Chat
A minimal client & server application for a chat system written in C++ which is currently in work.
However currently only linux is supported, but further OS variants will be added in the future.
The server-client communication is based on non-blocking sockets and TLS encryption v1.3 using OpenSSL.
To authenticate a user, a challenge-response procedure is implemented and supports flexible key types (however one should either use ED25510 or ML-DSA variants). A basic sqlite3 interface allows storage of user information and messages on server and client side. 

## TODO
- [x] Add support for at least 1 post-quantum cryptography (PQC) routine
- [ ] Non-Blocking Sockets epoll alternative (eg. kqueue for Apple, etc.)
- [ ] Client GUI (QT6)
- [ ] Add MLS or Double Ratchet E2E encryption
- [ ] Implement message storage in database

## Usage

Create certificate for server
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
``

## Acknowledgements
Please take a look at the following repositories which inspired parts/implementations inside this project:
- ENet (https://github.com/lsalzman/enet)