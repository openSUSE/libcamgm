#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/LogControl.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

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

        RequestGenerationData rgd = CA::getRootCARequestDefaults("./TestRepos/");
        CertificateIssueData  cid = CA::getRootCAIssueDefaults("./TestRepos/");

        std::list<RDNObject> dnl = rgd.getSubjectDN().getDN();
        std::list<RDNObject>::iterator dnit;

        for(dnit = dnl.begin(); dnit != dnl.end(); ++dnit)
        {
            cout << "DN Key " << (*dnit).getType() << endl;

            if((*dnit).getType() == "countryName")
            {
                (*dnit).setRDNValue("DE");
            }
            else if((*dnit).getType() == "commonName")
            {
                (*dnit).setRDNValue("Test CA");
            }
            else if((*dnit).getType() == "emailAddress")
            {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }

        DNObject dn(dnl);
        rgd.setSubjectDN(dn);

        CA::createRootCA("Test_CA", "system", rgd, cid, "./TestRepos/");

        path::PathInfo iKey("./TestRepos/Test_CA/cacert.key");
        path::PathInfo iReq("./TestRepos/Test_CA/cacert.req");
        path::PathInfo iCrt("./TestRepos/Test_CA/cacert.pem");

        if(iKey.isFile())
        {
            cout << iKey.toString() << " IS FILE" <<endl;

            if(iKey.size() > 0)
            {
                cout << "Size is greater then 0" << endl;
            }
            else
            {
                cout << "ERROR Size is 0" << iKey.size() << endl;
            }
        }
        else
        {
            cout << "ERROR ./TestRepos/Test_CA/cacert.key is not a file" <<endl;
        }

        if(iReq.isFile())
        {
            cout << iReq.toString() << " IS FILE" <<endl;

            if(iKey.size() > 0)
            {
                cout << "Size is greater then 0" << endl;
            }
            else
            {
                cout << "ERROR Size is 0" << endl;
            }
        }
        else
        {
            cout << "ERROR ./TestRepos/Test_CA/cacert.req is not a file" <<endl;
        }

        if(iCrt.isFile())
        {
            cout << iCrt.toString() << " IS FILE" <<endl;

            if(iKey.size() > 0)
            {
                cout << "Size is greater then 0" << endl;
            }
            else
            {
                cout << "ERROR Size is 0" << endl;
            }
        }
        else
        {
            cout << "ERROR ./TestRepos/Test_CA/cacert.pem is not a file" <<endl;
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
