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
                                                      "RemoveRequestTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        ca_mgm::Logger::setDefaultLogger(l);

        cout << "=================== start ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            std::vector<map<blocxx::String, blocxx::String> > ret;
            ret = ca.getRequestList();

            blocxx::String requestName = (*(ret[0].find("request"))).second;

            path::PathInfo reqFile("./TestRepos/Test_CA1/req/" + requestName + ".req");
            if(reqFile.exists())
            {
                ca.deleteRequest(requestName);

                reqFile.stat();
                if(!reqFile.exists())
                {
                    cout << "Delete Request successfull." << endl;
                }
                else
                {
                    cout << "Delete Request failed." << endl;
                }

                path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" + requestName + ".key");
                if(!keyFile.exists())
                {
                    cout << "Delete Key successfull." << endl;
                }
                else
                {
                    cout << "Delete Key failed." << endl;
                }
            }
            else
            {
                cout << "Request not found." << endl;
            }
        }
        cout << "DONE" << endl;
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
