#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

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
        
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "UpdateDBTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        limal::Logger::setDefaultLogger(l);
        
        cout << "=================== start Update DB ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            ca.updateDB();
            
            cout << "UpdateDB successfully executed" << endl;
        }

        cout << "=================== test wrong password ==================" << endl;
        
        try
        {
            CA ca2("Test_CA1", "tralla", "./TestRepos/");
            
            ca2.updateDB();
        }
        catch(RuntimeException &re)
        {
            cout << "Got RuntimeException. This is ok!" << endl;
        }
        cout << "=================== end Update DB ========================" << endl;
        
        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
