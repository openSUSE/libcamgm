#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathUtils.hpp>
#include <limal/Exception.hpp>
#include <limal/ca-mgm/CA.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;
        
        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "DeleteCATest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      LogAppender::ALL_CATEGORIES,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

        // fake the index.txt
        path::copyFile("./TestRepos/Test_CA1/index.txt", 
                       "./TestRepos/Test_CA/index.txt");

        try
        {
            CA::deleteCA("Test_CA", "system", false, "./TestRepos/");

        }
        catch(RuntimeException& e)
        {
            // this is a wanted exception
            cout << "Got expected exception" << endl;
            cerr << e.getFile() << ": " << e.type() << ": " << e.getMessage() << endl;
        }

        CA::deleteCA("Test_CA", "system", true, "./TestRepos/");
        
        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
