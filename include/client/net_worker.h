#ifndef NET_WORKER_H
#define NET_WORKER_H

#include <QObject>

#include "net/connector.h"

class NetWorker : public QObject
{
    QOBJECT
private:
    Connector* connector = nullptr;
    bool is_active = false;
public:
    NetWorker(QObject* parent = nullptr, Connector* connector=nullptr);
    ~NetWorker();

    void process();
//public slots:
    void connect(connect(std::string host, int port));
//signals:
};

#endif