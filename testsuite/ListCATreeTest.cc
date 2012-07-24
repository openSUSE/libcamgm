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
        logger.setLogLevel( logger::E_DEBUG );
        logger.logToStdErr();

        cout << "=================== start CA Tree List ======================" << endl;

        std::list<std::vector<std::string> > tree = CA::getCATree("./TestRepos3/");
        std::list<std::vector<std::string> >::const_iterator it_ext;

        for(it_ext = tree.begin(); it_ext != tree.end(); ++it_ext)
        {
            std::vector<std::string>::const_iterator it_int;

            for(it_int = (*it_ext).begin(); it_int != (*it_ext).end(); ++it_int)
            {
                cout << *it_int << "  " ;
            }
            cout << endl;
        }
        cout << "=================== end CA Tree List ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
