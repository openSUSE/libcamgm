#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/PathUtils.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/LocalManagement.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater2.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        // Logging
	boost::shared_ptr<LogControl::LineFormater> formater(new TestLineFormater2());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        // TestLineFormater2.hpp do not log errors
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

        try
        {
            CA::importCA("anyPolicyCA",
                         LocalManagement::readFile("./TestRepos/anyPolicyCA.pem"),
                         LocalManagement::readFile("./TestRepos/anyPolicyCA.key"),
                         "system", "./TestRepos/");
        }
        catch(ValueException& e)
        {
            // this is a wanted exception
            cout << "Got expected exception" << endl;
            cerr << e.getFile() << ": " << e.type() << ": " << e.getMessage() << endl;
        }

        path::PathInfo t("./TestRepos/anyPolicyCA/");
        if(t.exists() && t.isDir())
        {
            cout << "./TestRepos/anyPolicyCA/ exists" << endl;
        }

        t.stat("./TestRepos/anyPolicyCA/cacert.pem");
        if(t.exists() && t.isFile() && t.size() > 0)
        {
            cout << "./TestRepos/anyPolicyCA/cacert.pem exists" << endl;
        }

        t.stat("./TestRepos/anyPolicyCA/cacert.key");
        if(t.exists() && t.isFile() && t.size() > 0)
        {
            cout << "./TestRepos/anyPolicyCA/cacert.key exists" << endl;
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
