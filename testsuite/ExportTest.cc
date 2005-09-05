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
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

extern "C" {
#include <EXTERN.h>
#include <perl.h>
}

EXTERN_C void xs_init (pTHX);
PerlInterpreter *my_perl;

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("ExportTest");

int main(int argc, char **argv)
{
    char *embedding[] = { "", "-I../src/", "-MDynaLoader", "-MOPENSSL", "-MOPENSSL::CATools", "-e", 
                          "0" };
    
    PERL_SYS_INIT3(&argc,&argv,&env);
    my_perl = perl_alloc();
    perl_construct( my_perl );
    
    perl_parse(my_perl, xs_init, 7, embedding, NULL);
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    perl_run(my_perl);

    PerlRegEx r("ENCRYPTED");

    try {
        std::cout << "START" << std::endl;

        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             cat,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "ExportTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);

        
        CA ca("SUSEIPsecCA", "system", "./TestRepos3/");
        
        std::cout << "==================== ca.exportCACert(PEM); ======================" << std::endl; 

        ByteArray ba = ca.exportCACert(PEM);
        
        CertificateData cd = LocalManagement::getCertificate(ba, PEM);

        std::cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << std::endl;

        std::cout << "==================== ca.exportCACert(DER); ======================" << std::endl; 

        ba = ca.exportCACert(DER);
        
        cd = LocalManagement::getCertificate(ba, DER);

        std::cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << std::endl;

        std::cout << "==================== ca.exportCAKeyAsPEM(''); ======================" << std::endl; 

        ba = ca.exportCAKeyAsPEM("");
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCAKey.key");

        limal::path::PathInfo pi("./TestRepos3/testCAKey.key");

        if(pi.exists()) {

            std::cout << "Key exists" << std::endl;

            if(!r.match(LocalManagement::ba2str(ba))) {

                std::cout << "Key is decrypted" << std::endl;

                limal::path::removeFile("./TestRepos3/testCAKey.key");

            } else {

                std::cout << "Key is encrypted" << std::endl;
            }
        }

        std::cout << "==================== ca.exportCAKeyAsPEM('tralla'); ======================" << std::endl; 

        ba = ca.exportCAKeyAsPEM("tralla");
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCAKey2.key");

        pi.stat("./TestRepos3/testCAKey2.key");

        if(pi.exists()) {

            std::cout << "Key exists" << std::endl;

            if(!r.match(LocalManagement::ba2str(ba))) {

                std::cout << "Key is decrypted" << std::endl;

            } else {

                std::cout << "Key is encrypted" << std::endl;

                limal::path::removeFile("./TestRepos3/testCAKey2.key");
            }
        }


        std::cout << "==================== ca.exportCAKeyAsDER(); ======================" << std::endl; 

        ba = ca.exportCAKeyAsDER();
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCAKeyDER.key");

        pi.stat("./TestRepos3/testCAKeyDER.key");

        if(pi.exists() && pi.size() > 1000) {

            std::cout << "Key exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testCAKeyDER.key");

        }

        std::cout << "==================== ca.exportCAasPKCS12('tralla', false); ======================" << std::endl; 

        ba = ca.exportCAasPKCS12("tralla", false);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCA.p12");

        pi.stat("./TestRepos3/testCA.p12");

        if(pi.exists() && pi.size() > 2500) {

            std::cout << "Certificate exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testCA.p12");

        }

        std::cout << "==================== ca.exportCAasPKCS12('tralla', true); ======================" << std::endl; 

        ba = ca.exportCAasPKCS12("tralla", true);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCAChain.p12");

        pi.stat("./TestRepos3/testCAChain.p12");

        if(pi.exists() && pi.size() > 5400) {

            std::cout << "Certificate exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testCAChain.p12");

        }

        CA ca2("SUSEUserCA", "system", "./TestRepos3/");

        std::cout << "==================== ca.exportCertificate(PEM); ======================" << std::endl; 

        ba = ca2.exportCertificate("01:9528e1d8783f83b662fca6085a8c1467-1111161258", PEM);
        
        cd = LocalManagement::getCertificate(ba, PEM);

        std::cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << std::endl;

        std::cout << "==================== ca.exportCertificate(DER); ======================" << std::endl; 

        ba = ca2.exportCertificate("01:9528e1d8783f83b662fca6085a8c1467-1111161258", DER);
        
        cd = LocalManagement::getCertificate(ba, DER);

        std::cout << "Subject: " << cd.getSubjectDN().getOpenSSLString() << std::endl;


        std::cout << "==================== ca.exportCertificateKeyAsPEM(decr); ======================" << std::endl; 

        ba = ca2.exportCertificateKeyAsPEM("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                          "system", "");
        
        LocalManagement::writeFile(ba, "./TestRepos3/testKey.key");

        pi.stat("./TestRepos3/testKey.key");

        if(pi.exists()) {

            std::cout << "Key exists" << std::endl;

            if(!r.match(LocalManagement::ba2str(ba))) {

                std::cout << "Key is decrypted" << std::endl;

                limal::path::removeFile("./TestRepos3/testKey.key");

            } else {

                std::cout << "Key is encrypted" << std::endl;
            }
        }

        std::cout << "==================== ca.exportexportCertificateKeyAsPEM('tralla'); ======================" << std::endl; 

        ba = ca2.exportCertificateKeyAsPEM("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                          "system", "tralla");
        
        LocalManagement::writeFile(ba, "./TestRepos3/testKey2.key");

        pi.stat("./TestRepos3/testKey2.key");

        if(pi.exists()) {

            std::cout << "Key exists" << std::endl;

            if(!r.match(LocalManagement::ba2str(ba))) {

                std::cout << "Key is decrypted" << std::endl;

            } else {

                std::cout << "Key is encrypted" << std::endl;

                limal::path::removeFile("./TestRepos3/testKey2.key");
            }
        }

        std::cout << "==================== ca.exportCertificateKeyAsDER(); ======================" << std::endl; 

        ba = ca2.exportCertificateKeyAsDER("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                          "system");
        
        LocalManagement::writeFile(ba, "./TestRepos3/testKeyDER.key");

        pi.stat("./TestRepos3/testKeyDER.key");

        if(pi.exists() && pi.size() > 1000) {

            std::cout << "Key exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testKeyDER.key");

        }

        std::cout << "==================== ca.exportCertificateAsPKCS12(..., false); ======================" << std::endl; 

        ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", false);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCert.p12");

        pi.stat("./TestRepos3/testCert.p12");

        if(pi.exists() && pi.size() > 2500) {

            std::cout << "Certificate exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testCert.p12");

        }

        std::cout << "==================== ca.exportCertificateAsPKCS12(..., true); ======================" << std::endl; 

        ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", true);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCertChain.p12");

        pi.stat("./TestRepos3/testCertChain.p12");

        if(pi.exists() && pi.size() > 5400) {

            std::cout << "Certificate exists" << std::endl;
        
            limal::path::removeFile("./TestRepos3/testCertChain.p12");

        }

        std::cout << "==================== ca.exportCRL(PEM); ======================" << std::endl; 
        
        ba = ca2.exportCRL(PEM);
        
        CRLData crl = LocalManagement::getCRL(ba, PEM);

        std::cout << "Issuer: " << crl.getIssuerDN().getOpenSSLString() << std::endl;

        std::cout << "==================== ca.exportCRL(DER); ======================" << std::endl; 
        
        ba = ca2.exportCRL(DER);
        
        crl = LocalManagement::getCRL(ba, DER);

        std::cout << "Issuer: " << crl.getIssuerDN().getOpenSSLString() << std::endl;

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
