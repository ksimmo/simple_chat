#include <iostream>
#include <filesystem>
#include <signal.h>

#include <QtCore/QCoreApplication>
#include <QThread>
#include "logger.h"
#include "net/net.h"
#include "db/database.h"
#include "crypto/crypto.h"
#include "client/net_worker.h"

bool main_loop_run = true;

void quit_loop(int sig)
{
    main_loop_run = false;
}

//bob
std::vector<unsigned char> priv = {238,86,202,231,84,24,213,231,248,202,216,220,193,41,139,180,92,242,29,113,238,233,125,141,62,121,163,208,85,209,27,123};
std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};

//alice
std::vector<unsigned char> priv2 = {225,33,75,219,68,188,91,49,118,196,141,173,113,65,160,182,185,195,237,205,12,81,152,141,23,152,75,111,16,227,88,62};
std::vector<unsigned char> pub2 = {242,166,74,118,251,209,138,140,15,177,96,237,234,0,148,242,120,50,97,254,145,4,18,93,218,239,245,215,175,44,197,202};

int main(int argc, char* argv[])
{
    Logger& logger = Logger::instance(LogLevel::DEBUG, "client.log");

    bool alice = false; //is this client alice or bob (just for test case!)
    if(argc>1)
    {
        alice = true;
    }

    QCoreApplication app(argc, argv);
    signal(SIGINT, &quit_loop);
    initialize_socket();
    SSL_CTX* ctx = init_openssl();

    Database* db = new Database();
    db->connect("user.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); //create if not exists
    db->run_query("CREATE TABLE IF NOT EXISTS keys (type TEXT NOT NULL, id INTEGER, key BLOB NOT NULL, date TEXT);", nullptr);
    //db->run_query("INSERT INTO keys (type, id, key, date) VALUES(?, ?, ?);", "tibt", "TestUser", priv.size(), priv.data(), "-");

    //table for contacts
    db->run_query("CREATE TABLE IF NOT EXISTS contacts (type TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type TEXT NOT NULL, last_online TEXT);", nullptr);

    Connector* connector = new Connector(ctx);

    QThread* net_thread = new QThread();
    NetWorker* net_worker = new NetWorker(nullptr, connector, db, alice);
    net_worker->moveToThread(net_thread);
    //connect signals and slots
    //thread related ...
    QObject::connect(net_thread, &QThread::started, net_worker, &NetWorker::process);
    QObject::connect(net_worker, &NetWorker::finished, net_thread, &QThread::quit);
    //other

    net_thread->start();

    //connect
    QMetaObject::invokeMethod(net_worker, "connect", Qt::QueuedConnection, 
                Q_ARG(const std::string& , "127.0.0.1"), Q_ARG(int, 69100), Q_ARG(const std::string&, alice? "TestUser2" : "TestUser"),
                Q_ARG(const std::string&, "ED25519"), Q_ARG(const std::vector<unsigned char>&, alice ? priv2 : priv));

    //finish workers
    QThread::sleep(20);

    QMetaObject::invokeMethod(net_worker, "stop", Qt::QueuedConnection);
    QThread::sleep(1);
    //net_thread->wait();

    delete net_worker;
    delete net_thread;

    delete connector;
    delete db;

    cleanup_openssl(ctx);

    return 0;
}