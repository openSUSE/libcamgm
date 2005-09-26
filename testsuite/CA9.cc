#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main()
{
    PerlRegEx r("^!CHANGING DATA!.*$");

    try
    {
        cout << "START" << endl;
        
        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "CA9",
                                                      LogAppender::ALL_COMPONENTS,
                                                      LogAppender::ALL_CATEGORIES,
                                                      "%-5p %c - %m"
                                                  );
        limal::Logger::setDefaultLogger(l);
        
        cout << "=================== start CA List ======================" << endl;

        StringArray list = CA::getCAList("./TestRepos/");

        StringArray::const_iterator it;

        for(it = list.begin(); it != list.end(); ++it)
        {
            cout << *it << endl;
        }
        cout << "=================== end CA List ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
