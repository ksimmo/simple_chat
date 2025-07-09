#ifndef NET_WORKER_H
#define NET_WORKER_H

#include <QObject>

#include "net/net.h"
#include "crypto/crypto.h"

class NetWorker : public QObject
{
    Q_OBJECT
private:
    Connector* connector = nullptr;
    bool is_active = false;
    bool is_connected = false;
    bool alice = false; //just for testing

    Key key_identity;
    std::string user_name;

    void process_events();
    void process_packets();
public:
    NetWorker(QObject* parent = nullptr, Connector* connector=nullptr, bool is_alice=false);
    ~NetWorker();

    void process();
public slots:
    void connect(std::string host, int port, const std::string& name, const std::string& key_type, const std::vector<unsigned char>& key_priv);
    void disconnect();
    void stop();
signals:
    void finished();
    void message_received(std::string sender, std::vector<unsigned char> data);
};

#endif