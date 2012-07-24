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
	boost::shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

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
        catch(ValueException &re)
        {
            cout << "Got ValueException. This is ok!" << endl;
        }
        cout << "=================== end Update DB ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
