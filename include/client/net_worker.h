#ifndef NET_WORKER_H
#define NET_WORKER_H

#include <QObject>

#include "net/net.h"
#include "db/database.h"
#include "crypto/crypto.h"

class NetWorker : public QObject
{
    Q_OBJECT
private:
    Connector* connector = nullptr;
    Database* db = nullptr;
    bool is_active = false;
    bool is_connected = false;
    bool alice = false; //just for testing

    Key key_identity;
    std::string user_name;

    std::unordered_map<std::string, DoubleRatchet*> ratchets;

    void process_events();
    void process_packets();

    void update_prekey();
    void update_otkeys(std::size_t num);
public:
    NetWorker(QObject* parent = nullptr, Connector* connector=nullptr, Database* db=nullptr, bool is_alice=false);
    ~NetWorker();

    void process();
public slots:
    void connect(std::string host, int port, const std::string& name, const std::string& key_type, const std::vector<unsigned char>& key_priv);
    void disconnect();
    void stop();
    void request_online_status(std::string name);
    void request_user_keys(std::string name);
signals:
    void finished();
    void online_status_recevied(std::string name, bool status);
    void message_received(std::string sender, std::vector<unsigned char> data);
};

#endif