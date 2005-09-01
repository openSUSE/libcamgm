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

limal::Logger logger("ImportCATest");

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
                                                         "ImportCATest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);

        std::ifstream in("./TestRepos/importCATest.pem");
        
        if (!in) {
            
            std::cerr << "Cannot open file." << std::endl;

            return 1;
        }
        
        int    i         = 0;
        blocxx::String caCertificate;
        
        while(i != EOF) {
            
            i = in.get();
            caCertificate += static_cast<char>(i);
            
        }
        in.close();

        in.open("./TestRepos/importCATest.key");
        
        if (!in) {
            
            std::cerr << "Cannot open file." << std::endl;

            return 1;
        }
        
        i         = 0;
        blocxx::String caKey;
        
        while(i != EOF) {
            
            i = in.get();
            caKey += static_cast<char>(i);
            
        }
        in.close();
        
        
        try {

            CA::importCA("Test_CA3", caCertificate, caKey, "", "./TestRepos/");

        } catch(limal::ValueException& e) {

            std::cout << "Got expected exception" << std::endl;
            std::cerr << e << std::endl;
            
            // this is a wanted exception
        }

        CA::importCA("Test_CA3", caCertificate, caKey, "tralla", "./TestRepos/");
        
        limal::path::PathInfo t("./TestRepos/Test_CA3/");
        if(t.exists() && t.isDir()) {
            std::cout << "./TestRepos/Test_CA3/ exists" << std::endl;
        }

        t.stat("./TestRepos/Test_CA3/cacert.pem");
        if(t.exists() && t.isFile() && t.size() > 0) {
            std::cout << "./TestRepos/Test_CA3/cacert.pem exists" << std::endl;
        }

        t.stat("./TestRepos/Test_CA3/cacert.key");
        if(t.exists() && t.isFile() && t.size() > 0) {
            std::cout << "./TestRepos/Test_CA3/cacert.key exists" << std::endl;
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
