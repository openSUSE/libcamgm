#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathUtils.hpp>
#include <limal/Exception.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>

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
        //cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "ImportCATest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

        try
        {
            CA::importCA("Test_CA3",
                         LocalManagement::readFile("./TestRepos/importCATest.pem"),
                         LocalManagement::readFile("./TestRepos/importCATest.key"),
                         "", "./TestRepos/");
        }
        catch(ValueException& e)
        {
            // this is a wanted exception
            cout << "Got expected exception" << endl;
            cerr << e.getFile() << ": " << e.type() << ": " << e.getMessage() << endl;
        }

	    try
	    {
		    CA::importCA("Test_CA3",
		                 LocalManagement::readFile("./TestRepos/importCATest.pem"),
		                 LocalManagement::readFile("./TestRepos/importCATestEnc.key"),
		                 "wrong passwd", "./TestRepos/");
	    }
	    catch(ValueException& e)
	    {
            // this is a wanted exception
		    cout << "Got expected exception" << endl;
		    cerr << e.getFile() << ": " << e.type() << ": " << e.getMessage() << endl;
	    }

        CA::importCA("Test_CA3",
                     LocalManagement::readFile("./TestRepos/importCATest.pem"),
                     LocalManagement::readFile("./TestRepos/importCATest.key"),
                     "tralla", "./TestRepos/");

        path::PathInfo t("./TestRepos/Test_CA3/");
        if(t.exists() && t.isDir())
        {
            cout << "./TestRepos/Test_CA3/ exists" << endl;
        }

        t.stat("./TestRepos/Test_CA3/cacert.pem");
        if(t.exists() && t.isFile() && t.size() > 0)
        {
            cout << "./TestRepos/Test_CA3/cacert.pem exists" << endl;
        }

        t.stat("./TestRepos/Test_CA3/cacert.key");
        if(t.exists() && t.isFile() && t.size() > 0)
        {
            cout << "./TestRepos/Test_CA3/cacert.key exists" << endl;
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
