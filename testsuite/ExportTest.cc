#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
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
    PerlRegEx r("ENCRYPTED");

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
                                                      "ExportTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        ca_mgm::Logger::setDefaultLogger(l);


        CA ca("SUSEIPsecCA", "system", "./TestRepos3/");

        cout << "==================== ca.exportCACert(PEM); ======================" << endl;

        ByteBuffer ba = ca.exportCACert(E_PEM);

        CertificateData cd = LocalManagement::getCertificate(ba, E_PEM);

        cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << endl;

        cout << "==================== ca.exportCACert(DER); ======================" << endl;

        ba = ca.exportCACert(E_DER);

        cd = LocalManagement::getCertificate(ba, E_DER);

        cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << endl;

        cout << "==================== ca.exportCAKeyAsPEM(''); ======================" << endl;

        ba = ca.exportCAKeyAsPEM("");

        LocalManagement::writeFile(ba, "./TestRepos3/testCAKey.key");

        path::PathInfo pi("./TestRepos3/testCAKey.key");

        if(pi.exists())
        {
            cout << "Key exists" << endl;

            if(!r.match(std::string(ba.data(), ba.size())))
            {
                cout << "Key is decrypted" << endl;

                path::removeFile("./TestRepos3/testCAKey.key");
            }
            else
            {
                cout << "Key is encrypted" << endl;
            }
        }

        cout << "==================== ca.exportCAKeyAsPEM('tralla'); ======================" << endl;

        ba = ca.exportCAKeyAsPEM("tralla");

        LocalManagement::writeFile(ba, "./TestRepos3/testCAKey2.key");

        pi.stat("./TestRepos3/testCAKey2.key");

        if(pi.exists())
        {
            cout << "Key exists" << endl;

            if(!r.match(std::string(ba.data(), ba.size())))
            {
                cout << "Key is decrypted" << endl;
            }
            else
            {
                cout << "Key is encrypted" << endl;

                path::removeFile("./TestRepos3/testCAKey2.key");
            }
        }

        cout << "==================== ca.exportCAKeyAsDER(); ======================" << endl;

        ba = ca.exportCAKeyAsDER();

        LocalManagement::writeFile(ba, "./TestRepos3/testCAKeyDER.key");

        pi.stat("./TestRepos3/testCAKeyDER.key");

        if(pi.exists() && pi.size() > 1000)
        {
            cout << "Key exists" << endl;

            path::removeFile("./TestRepos3/testCAKeyDER.key");
        }

        cout << "=============== ca.exportCAasPKCS12('tralla', false); ===============" << endl;

        ba = ca.exportCAasPKCS12("tralla", false);

        LocalManagement::writeFile(ba, "./TestRepos3/testCA.p12");

        pi.stat("./TestRepos3/testCA.p12");

        if(pi.exists() && pi.size() > 2500)
        {
            cout << "Certificate exists" << endl;

            path::removeFile("./TestRepos3/testCA.p12");
        }

        cout << "================= ca.exportCAasPKCS12('tralla', true); =================" << endl;

        ba = ca.exportCAasPKCS12("tralla", true);

        LocalManagement::writeFile(ba, "./TestRepos3/testCAChain.p12");

        pi.stat("./TestRepos3/testCAChain.p12");

        if(pi.exists() && pi.size() > 5400)
        {
            cout << "Certificate exists" << endl;

            path::removeFile("./TestRepos3/testCAChain.p12");
        }

        CA ca2("SUSEUserCA", "system", "./TestRepos3/");

        cout << "==================== ca.exportCertificate(PEM); ======================" << endl;

        ba = ca2.exportCertificate("04:9528e1d8783f83b662fca6085a8c1467-1111161258", E_PEM);

        cd = LocalManagement::getCertificate(ba, E_PEM);

        cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << endl;

        cout << "==================== ca.exportCertificate(DER); ======================" << endl;

        ba = ca2.exportCertificate("04:9528e1d8783f83b662fca6085a8c1467-1111161258", E_DER);

        cd = LocalManagement::getCertificate(ba, E_DER);

        cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << endl;

        cout << "================== ca.exportCertificateKeyAsPEM(decr); ===================" << endl;

        ba = ca2.exportCertificateKeyAsPEM("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "");

        LocalManagement::writeFile(ba, "./TestRepos3/testKey.key");

        pi.stat("./TestRepos3/testKey.key");

        if(pi.exists())
        {
            cout << "Key exists" << endl;

            if(!r.match(std::string(ba.data(), ba.size())))
            {
                cout << "Key is decrypted" << endl;

                path::removeFile("./TestRepos3/testKey.key");

            }
            else
            {
                cout << "Key is encrypted" << endl;
            }
        }

        cout << "============ ca.exportexportCertificateKeyAsPEM('tralla'); =============" << endl;

        ba = ca2.exportCertificateKeyAsPEM("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla");

        LocalManagement::writeFile(ba, "./TestRepos3/testKey2.key");

        pi.stat("./TestRepos3/testKey2.key");

        if(pi.exists())
        {
            cout << "Key exists" << endl;

            if(!r.match(std::string(ba.data(), ba.size())))
            {
                cout << "Key is decrypted" << endl;

            }
            else
            {
                cout << "Key is encrypted" << endl;

                path::removeFile("./TestRepos3/testKey2.key");
            }
        }

        cout << "==================== ca.exportCertificateKeyAsDER(); ======================" << endl;

        ba = ca2.exportCertificateKeyAsDER("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system");

        LocalManagement::writeFile(ba, "./TestRepos3/testKeyDER.key");

        pi.stat("./TestRepos3/testKeyDER.key");

        if(pi.exists() && pi.size() > 1000)
        {
            cout << "Key exists" << endl;

            path::removeFile("./TestRepos3/testKeyDER.key");
        }

        cout << "============= ca.exportCertificateAsPKCS12(..., false); ==================" << endl;

        ba = ca2.exportCertificateAsPKCS12("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", false);

        LocalManagement::writeFile(ba, "./TestRepos3/testCert.p12");

        pi.stat("./TestRepos3/testCert.p12");

        if(pi.exists() && pi.size() > 2500)
        {
            cout << "Certificate exists" << endl;

            path::removeFile("./TestRepos3/testCert.p12");
        }

        cout << "=============== ca.exportCertificateAsPKCS12(..., true); ================" << endl;

        ba = ca2.exportCertificateAsPKCS12("04:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", true);

        LocalManagement::writeFile(ba, "./TestRepos3/testCertChain.p12");

        pi.stat("./TestRepos3/testCertChain.p12");

        if(pi.exists() && pi.size() > 5400)
        {
            cout << "Certificate exists" << endl;

            path::removeFile("./TestRepos3/testCertChain.p12");
        }

        cout << "==================== ca.exportCRL(PEM); ======================" << endl;

        ba = ca2.exportCRL(E_PEM);

        CRLData crl = LocalManagement::getCRL(ba, E_PEM);

        cout << "Issuer: " << crl.getIssuerDN().getOpenSSLString() << endl;

        cout << "==================== ca.exportCRL(DER); ======================" << endl;

        ba = ca2.exportCRL(E_DER);

        crl = LocalManagement::getCRL(ba, E_DER);

        cout << "Issuer: " << crl.getIssuerDN().getOpenSSLString() << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
