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

        cout << "=================== start ImportRequestTest ======================" << endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            std::string name = ca.importRequest(std::string("./TestRepos/importRequestTest.req"),
                                                   E_PEM);

            path::PathInfo pi("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi.exists())
            {
                cout << "File exists in the repository!" << endl;
            }

            sleep(1);

            name = ca.importRequest(std::string("./TestRepos/c293624b6a877f401407ce8f8f1f327e.req"),
                                    E_PEM);

            path::PathInfo pi2("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi2.exists())
            {
                cout << "File exists in the repository!" << endl;
            }
            sleep(1);

            name = ca.importRequest(std::string("./TestRepos/importRequestTest-DER.req"),
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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
