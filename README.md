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


## Acknowledgements
Please take a look at the following repositories which inspired parts/implementations inside this project:
- ENet (https://github.com/lsalzman/enet)