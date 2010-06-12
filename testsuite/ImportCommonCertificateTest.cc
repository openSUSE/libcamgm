#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathUtils.hpp>
#include <limal/Exception.hpp>
#include <limal/ByteBuffer.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "ImportCommonCertificateTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);

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
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
