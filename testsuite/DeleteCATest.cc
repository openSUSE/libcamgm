#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/PathUtils.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/CA.hpp>

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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
