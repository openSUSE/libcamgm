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

limal::Logger logger("SubCATest");

int main()
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
        
        blocxx::StringArray comp;
        comp.push_back("FATAL");
        comp.push_back("ERROR");
        comp.push_back("INFO");
        //comp.push_back("DEBUG");

        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             comp,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "SubCATest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        CA ca("Test_CA1", "system", "./TestRepos/");
        RequestGenerationData rgd = ca.getRequestDefaults(CA_Req);

        blocxx::List<RDNObject> dnl = rgd.getSubject().getDN();
        blocxx::List<RDNObject>::iterator dnit = dnl.begin();
        for(; dnit != dnl.end(); ++dnit) {
            std::cout << "DN Key " << (*dnit).getType() << std::endl;
            if((*dnit).getType() == "countryName") {
                (*dnit).setRDNValue("DE");
            } else if((*dnit).getType() == "commonName") {
                (*dnit).setRDNValue("Test Sub CA");
            }
            else if((*dnit).getType() == "emailAddress") {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);

        CertificateIssueData cid = ca.getIssueDefaults(CA_Cert);

        ca.createSubCA("SubCA_Test", "system", rgd, cid);

        std::cout << "RETURN Certificate " << std::endl;

        limal::path::PathInfo pi2("./TestRepos/SubCA_Test/cacert.pem");

        std::cout << "Sub CA exists: " << blocxx::Bool(pi2.exists()) << std::endl;
        
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
