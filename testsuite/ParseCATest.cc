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
        logger.setLogLevel( logger::E_DEBUG );
        logger.logToStdErr();

        cout << "=================== start ParseCATest ======================" << endl;
        {
            CA ca("Test_CA2", "system", "./TestRepos/");

            CertificateData cd = ca.getCA();

            std::vector<std::string> ret = cd.dump();

            std::vector<std::string>::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {
                cout << (*it) << endl;
            }

            cout << "=================== call verify ======================" << endl;

            ret = cd.verify();

            for(it  = ret.begin(); it != ret.end(); ++it)
            {
                cout << (*it) << endl;
            }
        }
        cout << "=================== end ParseCATest ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
