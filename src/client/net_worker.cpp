#include "client/net_worker.h"

NetWorker::NetWorker(QObject* parent, Connector* connector) : connector(connector)
{
}

NetWorker::~NetWorker()
{
}

void NetWorker::process()
{

}