#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        // Logging
        shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

        cout << "=================== start ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            std::vector<map<std::string, std::string> > ret;
            ret = ca.getRequestList();

            std::string requestName = (*(ret[0].find("request"))).second;

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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
