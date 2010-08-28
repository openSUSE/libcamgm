#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/Logger.hpp>
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

        CA ca("ca1_test", "system", "./TestRepos/");

        cout << "======================== getRequestDefaults =================" << endl;

        RequestGenerationData rgd = ca.getRequestDefaults(E_CA_Req);

        cout << "======================== call verify() =================" << endl;

        std::vector<std::string> a = rgd.verify();

        std::vector<std::string>::const_iterator it;

        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }

        cout << "======================== call dump() =================" << endl;

        std::vector<std::string> dump = rgd.dump();
        std::vector<std::string>::const_iterator it2;

        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
            }
        }

        cout << "======================== getIssueDefaults =================" << endl;

        CertificateIssueData cid = ca.getIssueDefaults(E_CA_Cert);

        cout << "======================== call verify() =================" << endl;

        a = cid.verify();

        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }

        cout << "======================== call dump() =================" << endl;

        dump = cid.dump();

        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
            }
        }

        cout << "======================== getCRLDefaults =================" << endl;

        CRLGenerationData cgd = ca.getCRLDefaults();

        cout << "======================== call verify() =================" << endl;

        a = cgd.verify();

        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }

        cout << "======================== call dump() =================" << endl;

        dump = cgd.dump();

        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
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
