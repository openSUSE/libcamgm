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
    PerlRegEx r("^!CHANGING DATA!.*$");

    try
    {
        cout << "START" << endl;

        // Logging
        shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        logger.setLogLevel( logger::E_DEBUG );
        logger.logToStdErr();

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
