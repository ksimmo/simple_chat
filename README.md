# Simple Chat
A minimal client & server application for a end2end encrypted chat system written in C++ (currently in development).
However currently only linux is supported, but further OS variants will be added in the future.
The server-client communication is based on non-blocking sockets and TLS encryption v1.3 using OpenSSL.
To authenticate a user, a challenge-response procedure is implemented and supports flexible key types (however one should either use ED25510 or ML-DSA variants). A basic sqlite3 interface allows storage of user information and messages on server and client side. 

## TODO
- [x] Add support for at least 1 post-quantum cryptography (PQC) routine
- [x] Perform X3DH (improve code, it seems to work -> maybe do a few more tests here)
- [ ] Non-Blocking Sockets epoll alternative (eg. kqueue for Apple -> test!, etc.)
- [ ] Client GUI (QT6)
- [x] Add MLS or Double Ratchet E2E encryption (currently Double Ratchet without header encryption)
- [ ] Add message delivery status
- [ ] Add configuration system

## Usage

Create certificate for server
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### SQLite3 Interface
The following example code shows how the sql interface is intended to use
```
//create a database interface and open/create a .db file
Database* database = new Database();
database->connect("test.db") //default is read-write only
//add flags for custom behaviour
database->connect("test.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) 

//run query
database->run_query("SELECT * FROM table;", nullptr); //select query does not need input data
std::vector<std::string> columns = database->column_names; //get column names of last query
std::vector<std::vector<DBEntry*>> values = database->values; //get queried data from last run

//if data is updated/inserted into the table
database->run_query("INSERT INTO table (col1, col2, col3) VALUES(?,?,?);", "itb",
        integer1, std::string, int buffer_size, void* buffer); //b always needs an additional int for size

//close
database->close(); //only needed if reuse is intended before delete
delete database;

```

## Server
Upon connection of a client and a succesfull initiation of the SSL handshake, the server waits a specified time window in which the client could try to login other wise the user will be disconnected. 
For a successfull login the server must be able to verify the challenge signature received from the client in a certain time period.
The server uses 3 sqlite tables to store user information, public keys for secret key exchanges and messages which could not be forwarded to the receiver due to not being logged in.


## Acknowledgements
Please take a look at the following repositories which inspired parts/implementations inside this project:
- ENet (https://github.com/lsalzman/enet)