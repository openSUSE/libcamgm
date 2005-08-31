#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

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

limal::Logger logger("ImportRequestTest");

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
                                                         "ImportRequestTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start ImportRequestTest ======================" << std::endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            blocxx::String name = ca.importRequest("./TestRepos/importRequestTest.req", PEM);
            
            limal::path::PathInfo pi("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi.exists()) {

                std::cout << "File exists in the repository!" << std::endl;

            }

            sleep(1);

            name = ca.importRequest("./TestRepos/c293624b6a877f401407ce8f8f1f327e.req", PEM);
            
            limal::path::PathInfo pi2("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi2.exists()) {

                std::cout << "File exists in the repository!" << std::endl;

            }

            sleep(1);

            name = ca.importRequest("./TestRepos/importRequestTest-DER.req", DER);
            
            limal::path::PathInfo pi3("./TestRepos/Test_CA1/req/" + name + ".req");
            if(pi3.exists()) {

                std::cout << "File exists in the repository!" << std::endl;

            }
        }

        std::cout << "=================== end ImportRequestTest ========================" << std::endl;
        
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
