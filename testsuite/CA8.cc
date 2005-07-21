#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>

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

limal::Logger logger("CA8");

int main(int argc, char **argv)
{
    PerlRegEx r("^!CHANGING DATA!.*$");

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
        
        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             LogAppender::ALL_CATEGORIES,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "CA8",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        RequestGenerationData rgd = CA::getRootCARequestDefaults("./TestRepos/");
        CertificateIssueData cid  = CA::getRootCAIssueDefaults("./TestRepos/");
        
        blocxx::List<RDNObject> dnl = rgd.getSubject().getDN();
        blocxx::List<RDNObject>::iterator dnit = dnl.begin();
        for(; dnit != dnl.end(); ++dnit) {
            if((*dnit).getType() == "countryName") {
                (*dnit).setRDN((*dnit).getType(), "DE");
            } else if((*dnit).getType() == "commonName") {
                (*dnit).setRDN((*dnit).getType(), "Test CA");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);
        
        CA::createRootCA("Test_CA", "system", rgd, cid, "./TestRepos/");
        
        path::PathInfo iKey("./TestRepos/Test_CA/cacert.key");
        path::PathInfo iReq("./TestRepos/Test_CA/cacert.req");
        path::PathInfo iCrt("./TestRepos/Test_CA/cacert.pem");

        if(iKey.isFile()) {
            std::cout << iKey.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << iKey.size() << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.key is not a file" <<std::endl;
        }

        if(iReq.isFile()) {
            std::cout << iReq.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.req is not a file" <<std::endl;
        }

        if(iCrt.isFile()) {
            std::cout << iCrt.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.pem is not a file" <<std::endl;
        }

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
