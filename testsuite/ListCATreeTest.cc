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
    try
    {
        cout << "START" << endl;
        
        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "ListCATreeTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      LogAppender::ALL_CATEGORIES,
                                                      "%-5p %c - %m"
                                                  );
        limal::Logger::setDefaultLogger(l);
        
        cout << "=================== start CA Tree List ======================" << endl;

        List<Array<blocxx::String> > tree = CA::getCATree("./TestRepos3/");
        List<Array<blocxx::String> >::const_iterator it_ext;

        for(it_ext = tree.begin(); it_ext != tree.end(); ++it_ext)
        {
            Array<blocxx::String>::const_iterator it_int;

            for(it_int = (*it_ext).begin(); it_int != (*it_ext).end(); ++it_int)
            {
                cout << *it_int << "  " ;
            }
            cout << endl;
        }
        cout << "=================== end CA Tree List ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
