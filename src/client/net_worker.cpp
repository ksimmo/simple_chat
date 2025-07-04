#include <QtCore/QCoreApplication>
#include "client/net_worker.h"

NetWorker::NetWorker(QObject* parent, Connector* connector) : connector(connector)
{
}

NetWorker::~NetWorker()
{
}

void NetWorker::process()
{
    //initialize connector
    this->is_active = true;
    while(this->is_active && this->connector->is_initialized())
    {
        if(this->connector->is_initialized())
            connector->step(100);
        //else
            //wait a bit maybe
        QCoreApplication::processEvents();
    }
}

void NetWorker::connect(std::string host, int port)
{
    //initialize connector
    this->connector->initialize(CONN_CLIENT, host, port, 100);
    this->process();
}

void NetWorker::shutdown()
{
    if(this->connector->is_initialized())
        this->connector->shutdown();
}