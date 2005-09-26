#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        
        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "CA8",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        limal::Logger::setDefaultLogger(l);
        
        RequestGenerationData rgd = CA::getRootCARequestDefaults("./TestRepos/");
        CertificateIssueData  cid = CA::getRootCAIssueDefaults("./TestRepos/");
        
        List<RDNObject> dnl = rgd.getSubject().getDN();
        List<RDNObject>::iterator dnit;

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
        rgd.setSubject(dn);
        
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
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
