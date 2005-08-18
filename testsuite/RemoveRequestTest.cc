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

limal::Logger logger("RemoveRequestTest");

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
                                                         "RemoveRequestTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start ======================" << std::endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getRequestList();

            blocxx::String requestName = (*(ret[0].find("request"))).second;
            
            limal::path::PathInfo reqFile("./TestRepos/Test_CA1/req/" + requestName + ".req");
            if(reqFile.exists()) {

                ca.deleteRequest(requestName);

                reqFile.stat();
                if(!reqFile.exists()) {
                    std::cout << "Delete Request successfull." << std::endl;
                } else {
                    std::cout << "Delete Request failed." << std::endl;
                }

                limal::path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" + requestName + ".key");
                if(!keyFile.exists()) {
                    std::cout << "Delete Key successfull." << std::endl;
                } else {
                    std::cout << "Delete Key failed." << std::endl;
                }

            } else {
                std::cout << "Request not found." << std::endl;
            }

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
