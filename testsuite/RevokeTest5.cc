#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/CRLReason.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

// FIXME: need to be removed
#include <Utils.hpp>

using namespace blocxx;

using namespace ca_mgm;
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
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "RevokeTest5",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        ca_mgm::Logger::setDefaultLogger(l);

        CA ca("Test_CA1", "system", "./TestRepos/");
        RequestGenerationData rgd = ca.getRequestDefaults(E_Server_Req);

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
                (*dnit).setRDNValue("Test Certificate for revocation 5 oid test");
            }
            else if((*dnit).getType() == "emailAddress")
            {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }

        DNObject dn(dnl);
        rgd.setSubjectDN(dn);

        CertificateIssueData cid = ca.getIssueDefaults(E_Server_Cert);

        std::string c = ca.createCertificate("system", rgd, cid, E_Server_Cert);

        cout << "RETURN Certificate " << endl;

        path::PathInfo pi("./TestRepos/Test_CA1/newcerts/" + c + ".pem");

        cout << "Certificate exists: " << Bool(pi.exists()) << endl;

        cout << "Try to revoke it" << endl;

        CRLReason reason("certificateHold");
        reason.setHoldInstruction("1.6.21.43");

        ca.revokeCertificate(c, reason);

        PerlRegEx r0("^([0-9a-fA-F]+):.*");
        std::vector<std::string> serial = r0.capture(c);

        ifstream in ("./TestRepos/Test_CA1/index.txt");

        while(1)
        {
            std::string line = str::getline(in);

            PerlRegEx r1("^R.+holdInstruction,1.6.21.43\\t"+
                         serial[1]+"\\t.*");

            if(r1.match(line))
            {
                cout << "Found revoked certificate " << endl;
            }

            if(line.empty()) break;
        }

        cout << "Create a CRL" << endl;

        CRLGenerationData cgd = ca.getCRLDefaults();

        ca.createCRL(cgd);

        path::PathInfo pi2("./TestRepos/Test_CA1/crl/crl.pem");
        if(pi2.size() > 0)
        {
            cout << "CRL file available and greater then 0" << endl;
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
