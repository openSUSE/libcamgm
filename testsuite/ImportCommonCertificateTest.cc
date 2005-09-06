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

limal::Logger logger("ImportCommonCertificateTest");

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
                                                         "ImportCommonCertificateTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);

        
        CA ca2("SUSEUserCA", "system", "./TestRepos3/");
        
        std::cout << "==================== ca.exportCertificateAsPKCS12(..., false); ======================" << std::endl; 
        
        ByteArray ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", false);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCert.p12");

        limal::path::PathInfo pi("./TestRepos3/testCert.p12");

        if(pi.exists() && pi.size() > 2500) {

            std::cout << "Certificate exists" << std::endl;
        }
        
        std::cout << "==================== importAsLocalCertificate() ======================" << std::endl; 

        LocalManagement::importAsLocalCertificate(ba, //pi.toString(),
                                                  "tralla",
                                                  "./TestRepos3/localTest/certs/",
                                                  "./TestRepos3/localTest/servercerts/servercert.pem",
                                                  "./TestRepos3/localTest/servercerts/serverkey.pem");

        pi.stat("./TestRepos3/localTest/servercerts/servercert.pem");
        if(pi.exists()) {

            std::cout << "servercert.pem exists" << std::endl;

        }
        pi.stat("./TestRepos3/localTest/servercerts/serverkey.pem");
        if(pi.exists() && pi.hasPerm(0600)) {

            std::cout << "serverkey.pem exists and has permissions 0600" << std::endl;

        }
        pi.stat("./TestRepos3/localTest/certs/YaST-CA.pem");
        if(pi.exists()) {

            std::cout << "CA exists !WRONG!" << std::endl;

        } else {

            std::cout << "CA do not exists ! OK !" << std::endl;
        }

        limal::path::removeFile("./TestRepos3/testCert.p12");

        std::cout << "==================== ca.exportCertificateAsPKCS12(..., true); ======================" << std::endl; 

        ba = ca2.exportCertificateAsPKCS12("01:9528e1d8783f83b662fca6085a8c1467-1111161258",
                                           "system", "tralla", true);
        
        LocalManagement::writeFile(ba, "./TestRepos3/testCertChain.p12");

        pi.stat("./TestRepos3/testCertChain.p12");

        if(pi.exists() && pi.size() > 5400) {

            std::cout << "Certificate exists" << std::endl;
        
        }

        std::cout << "==================== importAsLocalCertificate(Chain) ======================" << std::endl; 

        LocalManagement::importAsLocalCertificate(pi.toString(),
                                                  "tralla",
                                                  "./TestRepos3/localTest/certs2/",
                                                  "./TestRepos3/localTest/servercerts/servercert2.pem",
                                                  "./TestRepos3/localTest/servercerts/serverkey2.pem");

        pi.stat("./TestRepos3/localTest/servercerts/servercert2.pem");
        if(pi.exists()) {

            std::cout << "servercert.pem exists" << std::endl;

        }
        pi.stat("./TestRepos3/localTest/servercerts/serverkey2.pem");
        if(pi.exists() && pi.hasPerm(0600)) {

            std::cout << "serverkey.pem exists and has permissions 0600" << std::endl;

        }
        pi.stat("./TestRepos3/localTest/certs2/YaST-CA.pem");
        if(pi.exists()) {

            std::cout << "CA exists" << std::endl;

        }

        limal::path::removeFile("./TestRepos3/testCertChain.p12");

        limal::path::removeDirRecursive("./TestRepos3/localTest/");


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
