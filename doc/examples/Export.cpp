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
                                                      "Export",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                  );
        limal::Logger::setDefaultLogger(l);
        
        CA ca("MyRootCA", "system");

        
        // export CA certificate in PEM format ----------------------------
        
        ByteBuffer ba = ca.exportCACert(E_PEM);

        
        // export CA certificate in DER format ----------------------------
        
        ba = ca.exportCACert(E_DER);
        

        // export CA private key in PEM format (decrypted) ----------------

        ba = ca.exportCAKeyAsPEM("");
        
        LocalManagement::writeFile(ba, "./CAKey.key");


        // export CA private key in PEM format (encrypted) ----------------

        ba = ca.exportCAKeyAsPEM("tralla");
        
        LocalManagement::writeFile(ba, "./CAKey2.key");


        // export CA private key in DER format (decrypted) ----------------

        ba = ca.exportCAKeyAsDER();
        
        LocalManagement::writeFile(ba, "./CAKeyDER.key");


        // export CA in PKCS12 format (without CA chain) ------------------

        ba = ca.exportCAasPKCS12("tralla", false);
        
        LocalManagement::writeFile(ba, "./CA.p12");


        // export CA in PKCS12 format (with CA chain) ---------------------

        ba = ca.exportCAasPKCS12("tralla", true);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCAChain.p12");


        
        CA ca2("MyUserCA", "system");

        // export certificate in PEM format -------------------------------

        ba = ca2.exportCertificate("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                   E_PEM);
        

        // export certificate in DER format -------------------------------

        ba = ca2.exportCertificate("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                   E_DER);
        

        // export private key in PEM format (decrypted) -------------------

        ba = ca2.exportCertificateKeyAsPEM("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "");
        
        LocalManagement::writeFile(ba, "./Key.key");


        // export private key in PEM format (encrypted) -------------------

        ba = ca2.exportCertificateKeyAsPEM("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla");
        
        LocalManagement::writeFile(ba, "./Key2.key");


        // export private key in DER format (decrypted) ----------------

        ba = ca2.exportCertificateKeyAsDER("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system");
        
        LocalManagement::writeFile(ba, "./TestRepos3/KeyDER.key");


        // export certificate in PKCS12 format (without CA chain) ------

        ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", false);
        
        LocalManagement::writeFile(ba, "./Cert.p12");

        
        // export certificate in PKCS12 format (with CA chain) ---------

        ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", true);
        
        LocalManagement::writeFile(ba, "./TestRepos3/CertChain.p12");

        
        // export CRL in PEM format ------------------------------------
        
        ba = ca2.exportCRL(E_PEM);
        

        // export CRL in DER format ------------------------------------
        
        ba = ca2.exportCRL(E_DER);
        
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }
    
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
