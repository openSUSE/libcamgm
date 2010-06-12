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

using namespace ca_mgm;
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
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "ImportRequestTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

        cout << "=================== start ImportRequestTest ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            blocxx::String name = ca.importRequest(blocxx::String("./TestRepos/importRequestTest.req"),
                                                   E_PEM);

            path::PathInfo pi("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi.exists())
            {
                cout << "File exists in the repository!" << endl;
            }

            sleep(1);

            name = ca.importRequest(blocxx::String("./TestRepos/c293624b6a877f401407ce8f8f1f327e.req"),
                                    E_PEM);

            path::PathInfo pi2("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi2.exists())
            {
                cout << "File exists in the repository!" << endl;
            }
            sleep(1);

            name = ca.importRequest(blocxx::String("./TestRepos/importRequestTest-DER.req"),
                                    E_DER);

            path::PathInfo pi3("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi3.exists())
            {
                cout << "File exists in the repository!" << endl;
            }
        }

        cout << "=================== end ImportRequestTest ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(blocxx::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
