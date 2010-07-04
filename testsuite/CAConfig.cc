#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>

#include <blocxx/String.hpp>
#include <limal/Logger.hpp>
#include <limal/ca-mgm/CAConfig.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    cout << "START" << endl;

    // Logging
    LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                  "CAConfig",
                                                  LogAppender::ALL_COMPONENTS,
                                                  LogAppender::ALL_CATEGORIES,
                                                  "%-5p %c - %m"
                                                  );
    ca_mgm::Logger::setDefaultLogger(l);

    CAConfig *config    = new CAConfig("openssl.cnf.tmpl");
    CAConfig *configNew = config->clone("openssl.cnf.tmpl.test");

    LIMAL_SLOG(ca_mgm::Logger("ca-mgm"),
               "DEBUG", "file openssl.cnf.tmpl.test parsed.");

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
