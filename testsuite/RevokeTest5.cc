#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/CRLReason.hpp>
#include <ca-mgm/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

// FIXME: need to be removed
#include <Utils.hpp>

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
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

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

        cout << "Certificate exists: " << str::toString(pi.exists()) << endl;

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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
