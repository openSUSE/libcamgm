#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/CRLReason.hpp>

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
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "RevokeCertificate",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        limal::Logger::setDefaultLogger(l);
        
        CA ca("Test_CA1", "system", "./TestRepos/");

        // ------------------------ get request defaults -------------------

        RequestGenerationData rgd = ca.getRequestDefaults(E_Server_Req);

        List<RDNObject> dnl = rgd.getSubject().getDN();
        List<RDNObject>::iterator dnit;
        
        // ------------------------ fill the Subject (DN) -------------------

        for(dnit = dnl.begin(); dnit != dnl.end(); ++dnit)
        {
            cout << "DN Key " << (*dnit).getType() << endl;
            
            if((*dnit).getType() == "countryName")
            {
                (*dnit).setRDNValue("DE");
            }
            else if((*dnit).getType() == "commonName")
            {
                (*dnit).setRDNValue("Test Certificate for revocation 2");
            }
            else if((*dnit).getType() == "emailAddress")
            {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);

        // ------------------------ get issue defaults ---------------------

        CertificateIssueData cid = ca.getIssueDefaults(E_Server_Cert);

        // ------------------------ create a certificate -------------------

        blocxx::String c = ca.createCertificate("system", rgd, cid,
                                                E_Server_Cert);

        cout << "RETURN Certificate " << endl;

        // ------------------------ set a CRL reason -----------------------

        CRLReason reason("certificateHold");
        reason.setHoldInstruction("holdInstructionCallIssuer");

        // ------------------------ revoke the certificate -----------------

        ca.revokeCertificate(c, reason);

        // ------------------------ get CRL defaults -----------------------

        CRLGenerationData cgd = ca.getCRLDefaults();
        
        // ------------------------ create a CRL ---------------------------

        ca.createCRL(cgd);

        // The CRL is now available at './TestRepos/Test_CA1/crl/crl.pem'

    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
