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
        StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        
        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "CreateRootCA",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        limal::Logger::setDefaultLogger(l);
        
        RequestGenerationData rgd = CA::getRootCARequestDefaults("./TestRepos/");
        CertificateIssueData  cid = CA::getRootCAIssueDefaults("./TestRepos/");
        
        List<RDNObject> dnl = rgd.getSubjectDN().getDN();
        List<RDNObject>::iterator dnit;

        for(dnit = dnl.begin(); dnit != dnl.end(); ++dnit)
        {
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

        // The CA request is now available at './TestRepos/Test_CA/cacert.req'
        
        // The CA private key is now available at './TestRepos/Test_CA/cacert.key'
        
        // The CA certificate is now available at './TestRepos/Test_CA/cacert.pem'
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}
