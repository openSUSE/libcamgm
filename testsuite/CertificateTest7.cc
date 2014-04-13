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
                (*dnit).setRDNValue("Test Server Certificate/SUSE Inc.\\Gmbh");
            }
            else if((*dnit).getType() == "emailAddress")
            {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }

        CertificateIssueData cid = ca.getIssueDefaults(E_Server_Cert);
        DNObject dn(dnl);
        rgd.setSubjectDN(dn);

        /* ****************** SHA224 ********************** */
        rgd.setMessageDigest(E_SHA224);
        std::string r = ca.createRequest("system", rgd, E_Server_Req);
        RequestData rd = ca.getRequest(r);

        if (rd.getSignatureAlgorithm() == E_SHA224RSA )
        {
            cout << "Request with signature Algorithm sha224WithRSAEncryption" << endl;
        }

        cid.setMessageDigest(E_SHA224);

        std::string     c  = ca.issueCertificate(r, cid, E_Server_Cert);
        CertificateData cd = ca.getCertificate(c);

        if (cd.getSignatureAlgorithm() == E_SHA224RSA )
        {
            cout << "Certificate with signature Algorithm sha224WithRSAEncryption" << endl;
        }

        sleep(2); // We have a request with the same name. So sleep 2 sec. to get a difference in the timestamp

        /* ****************** SHA256 ********************** */
        rgd.setMessageDigest(E_SHA256);
        r  = ca.createRequest("system", rgd, E_Server_Req);
        rd = ca.getRequest(r);

        if (rd.getSignatureAlgorithm() == E_SHA256RSA )
        {
            cout << "Request with signature Algorithm sha256WithRSAEncryption" << endl;
        }

        cid.setMessageDigest(E_SHA256);

        c  = ca.issueCertificate(r, cid, E_Server_Cert);
        cd = ca.getCertificate(c);

        if (cd.getSignatureAlgorithm() == E_SHA256RSA )
        {
            cout << "Certificate with signature Algorithm sha256WithRSAEncryption" << endl;
        }

        sleep(2); // We have a request with the same name. So sleep 2 sec. to get a difference in the timestamp

        /* ****************** SHA384 ********************** */
        rgd.setMessageDigest(E_SHA384);
        r  = ca.createRequest("system", rgd, E_Server_Req);
        rd = ca.getRequest(r);

        if (rd.getSignatureAlgorithm() == E_SHA384RSA )
        {
            cout << "Request with signature Algorithm sha3846WithRSAEncryption" << endl;
        }

        cid.setMessageDigest(E_SHA384);

        c  = ca.issueCertificate(r, cid, E_Server_Cert);
        cd = ca.getCertificate(c);

        if (cd.getSignatureAlgorithm() == E_SHA384RSA )
        {
            cout << "Certificate with signature Algorithm sha384WithRSAEncryption" << endl;
        }

        sleep(2); // We have a request with the same name. So sleep 2 sec. to get a difference in the timestamp

        /* ****************** SHA512 ********************** */
        rgd.setMessageDigest(E_SHA512);
        r  = ca.createRequest("system", rgd, E_Server_Req);
        rd = ca.getRequest(r);

        if (rd.getSignatureAlgorithm() == E_SHA512RSA )
        {
            cout << "Request with signature Algorithm sha5126WithRSAEncryption" << endl;
        }

        cid.setMessageDigest(E_SHA512);

        c  = ca.issueCertificate(r, cid, E_Server_Cert);
        cd = ca.getCertificate(c);

        if (cd.getSignatureAlgorithm() == E_SHA512RSA )
        {
            cout << "Certificate with signature Algorithm sha512WithRSAEncryption" << endl;
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
