#ifndef NET_WORKER_H
#define NET_WORKER_H

#include <QObject>

#include "net/connector.h"

class NetWorker : public QObject
{
    QOBJECT
private:
    Connector* connector = nullptr;
public:
    NetWorker(QObject* parent = nullptr, Connector* connector=nullptr);
    ~NetWorker();

    void process();
//public slots:
    //void connect();
//signals:
};

#endif