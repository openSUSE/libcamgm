#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/PathUtils.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/LocalManagement.hpp>

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

        CA ca2("SUSEUserCA", "system", "./TestRepos3/");

        cout << "============ ca.exportCertificateAsPKCS12(..., false); ===========" << endl;

        ByteBuffer ba = ca2.exportCertificateAsPKCS12("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                                      "system", "tralla", false);

        LocalManagement::writeFile(ba, "./TestRepos3/testCert.p12");

        path::PathInfo pi("./TestRepos3/testCert.p12");
        if(pi.exists() && pi.size() > 2500)
        {
            cout << "Certificate exists" << endl;
        }

        cout << "================= importAsLocalCertificate() ==================" << endl;

        LocalManagement::importAsLocalCertificate(ba,
                                                  "tralla",
                                                  "./TestRepos3/localTest/certs/",
                                                  "./TestRepos3/localTest/servercerts/servercert.pem",
                                                  "./TestRepos3/localTest/servercerts/serverkey.pem");

        pi.stat("./TestRepos3/localTest/servercerts/servercert.pem");
        if(pi.exists())
        {
            cout << "servercert.pem exists" << endl;
        }

        pi.stat("./TestRepos3/localTest/servercerts/serverkey.pem");
        if(pi.exists() && pi.hasPerm(0600))
        {
            cout << "serverkey.pem exists and has permissions 0600" << endl;
        }

        pi.stat("./TestRepos3/localTest/certs/YaST-CA.pem");
        if(pi.exists())
        {
            cout << "CA exists ! OK!" << endl;
        }
        else
        {
            cout << "CA do not exists ! WRONG !" << endl;
        }

        pi.stat("./TestRepos3/localTest/certs/YaST-CA-0.pem");
        if(pi.exists())
        {
            cout << "YaST-CA-0 exists !WRONG!" << endl;
        }
        else
        {
            cout << "YaST-CA-0 do not exists ! OK !" << endl;
        }

        path::removeFile("./TestRepos3/testCert.p12");

        cout << "============ ca.exportCertificateAsPKCS12(..., true); ============" << endl;

        ba = ca2.exportCertificateAsPKCS12("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", true);

        LocalManagement::writeFile(ba, "./TestRepos3/testCertChain.p12");

        pi.stat("./TestRepos3/testCertChain.p12");
        if(pi.exists() && pi.size() > 5400)
        {
            cout << "Certificate exists" << endl;
        }

        cout << "================ importAsLocalCertificate(Chain) ==================" << endl;

        LocalManagement::importAsLocalCertificate(pi.toString(),
                                                  "tralla",
                                                  "./TestRepos3/localTest/certs2/",
                                                  "./TestRepos3/localTest/servercerts/servercert2.pem",
                                                  "./TestRepos3/localTest/servercerts/serverkey2.pem");

        pi.stat("./TestRepos3/localTest/servercerts/servercert2.pem");
        if(pi.exists())
        {
            cout << "servercert.pem exists" << endl;
        }

        pi.stat("./TestRepos3/localTest/servercerts/serverkey2.pem");
        if(pi.exists() && pi.hasPerm(0600))
        {
            cout << "serverkey.pem exists and has permissions 0600" << endl;
        }

        pi.stat("./TestRepos3/localTest/certs2/YaST-CA.pem");
        if(pi.exists())
        {
            cout << "CA exists" << endl;
        }

        pi.stat("./TestRepos3/localTest/certs2/YaST-CA-0.pem");
        if(pi.exists())
        {
            cout << "YaST-CA-0 exists ! OK !" << endl;
        }
        else
        {
            cout << "YaST-CA-0 do not exists ! WRONG !" << endl;
        }

        path::removeFile("./TestRepos3/testCertChain.p12");
        path::removeDirRecursive("./TestRepos3/localTest/");

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
