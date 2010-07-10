#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    PerlRegEx r("^!CHANGING DATA!.*$");

    try
    {
        cout << "START" << endl;

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "CA9",
                                                      LogAppender::ALL_COMPONENTS,
                                                      LogAppender::ALL_CATEGORIES,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

        cout << "=================== start CA List ======================" << endl;

        std::vector<std::string> list = CA::getCAList("./TestRepos/");

        std::vector<std::string>::const_iterator it;

        for(it = list.begin(); it != list.end(); ++it)
        {
            cout << *it << endl;
        }
        cout << "=================== end CA List ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
