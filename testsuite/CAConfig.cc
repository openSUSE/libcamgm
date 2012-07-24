
#include <ca-mgm/String.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/CAConfig.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    cout << "START" << endl;

    // Logging

    boost::shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
    LogControl logger = LogControl::instance();
    logger.setLineFormater( formater );
    logger.setLogLevel( logger::E_DEBUG );
    logger.logToStdErr();

    CAConfig *config    = new CAConfig("openssl.cnf.tmpl");
    CAConfig *configNew = config->clone("openssl.cnf.tmpl.test");

    _DBG("ca-mgm") << "file openssl.cnf.tmpl.test parsed.";

    configNew->setValue ("v3_req_server", "basicConstraints", "CA:TRUE");
    configNew->deleteValue ("v3_req_server", "keyUsage");

    CAConfig *configDump = new CAConfig("openssl.cnf.tmpl.test");
    configDump->dump();

    typedef std::list<std::string> StringList;
    StringList listKey = config->getKeylist("ca");

    cout << "Key for section : ca" << endl;

    for (StringList::iterator i = listKey.begin();
         i != listKey.end(); i++)
    {
        cout << "key   " << *i <<endl;
    }

    delete (config);
    delete (configNew);
    delete (configDump);

    cout << "DONE" << endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
