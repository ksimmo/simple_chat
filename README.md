# Simple Chat
A simple client & server application for a chat system written in C++ (currently in work).
The server-client communication is based on non-blocking sockets and TLS encryption using OpenSSL.

## TODO
- [ ] Non-Blocking Sockets epoll alternative
- [x] SSL Handshake
- [ ] Packet System
- [ ] SQLite database for messages and users
- [ ] Client GUI (QT6)
- [ ] User authentication system (ECDSA?)
- [ ] Maybe add MLS or Double Ratchet E2E encryption

## Usage

Create certificate for server
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```