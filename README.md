# Simple Chat
A simple client & server application for a chat system written in C++ (currently in work).
The server-client communication is based on non-blocking sockets and TLS encryption using OpenSSL.

## TODO
- [ ] Non-Blocking Sockets epoll alternative
- [x] SSL Handshake
- [x] Packet System
- [ ] SQLite database for messages and users
- [ ] Client GUI (QT6)
- [ ] User authentication system (Curve25519)
- [ ] Maybe add MLS or Double Ratchet E2E encryption

## Server
The servers main task is to reroute the messages to the corresponding receiver 

## Usage

Create certificate for server
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```