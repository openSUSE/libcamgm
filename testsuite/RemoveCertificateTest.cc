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

limal::Logger logger("RemoveCertificateTest");

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
                                                         "RemoveCertificateTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start ======================" << std::endl;
        {
            CA ca("Test_CA1", "system", "./TestRepos/");

            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getCertificateList();

            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >::const_iterator it = ret.begin();
            int i = 0;
            for(; it != ret.end(); ++it) {
            
                blocxx::String certificateName = (*((*it).find("certificate"))).second;
                blocxx::String state           = (*((*it).find("status"))).second;

                PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
                StringArray sa = p.capture(certificateName);

                if(sa.size() != 3) {
                    std::cerr << "Can not parse certificate name ... continue." << std::endl;
                    continue;
                }

                blocxx::String serial  = sa[1];
                blocxx::String request = sa[2];

                if(i == 0 && state != "Valid") {

                    limal::path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                                   certificateName + ".pem");
                    if(certFile.exists()) {
                        
                        ca.deleteCertificate(certificateName);

                        certFile.stat();
                        if(!certFile.exists()) {
                            std::cout << "Take 0: Delete Certificate successfull." << std::endl;
                        } else {
                            std::cout << "Take 0: Delete Certificate failed." << std::endl;
                        }

                        limal::path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" +
                                                      request + ".key");
                        if(!keyFile.exists()) {
                            std::cout << "Take 0: Delete Key successfull." << std::endl;
                        } else {
                            std::cout << "Take 0: Delete Key failed." << std::endl;
                        }

                        limal::path::PathInfo reqFile("./TestRepos/Test_CA1/req/" +
                                                      request + ".req");
                        if(!reqFile.exists()) {
                            std::cout << "Take 0: Delete Request successfull." << std::endl;
                        } else {
                            std::cout << "Take 0: Delete Request failed." << std::endl;
                        }
                        
                    } else {
                        std::cout << "Take 0: Certificate not found." << std::endl;
                    }
                    i++;
                } else if(i == 1 && state != "Valid") {
                    limal::path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                                   certificateName + ".pem");
                    if(certFile.exists()) {
                        
                        ca.deleteCertificate(certificateName, false);
                        
                        certFile.stat();
                        if(!certFile.exists()) {
                            std::cout << "Take 1: Delete Certificate successfull." << std::endl;
                        } else {
                            std::cout << "Take 1: Delete Certificate failed." << std::endl;
                        }

                        limal::path::PathInfo keyFile("./TestRepos/Test_CA1/keys/" +
                                                      request + ".key");
                        if(!keyFile.exists()) {
                            std::cout << "Take 1: Key not exists. !!! Wrong !!!" << std::endl;
                        } else {
                            std::cout << "Take 1: Key still exists. !!! OK !!!" << std::endl;
                        }

                        limal::path::PathInfo reqFile("./TestRepos/Test_CA1/req/" +
                                                      request + ".req");
                        if(!reqFile.exists()) {
                            std::cout << "Take 1: Request not exists. !!! Wrong !!!" << std::endl;
                        } else {
                            std::cout << "Take 1: Request still exists. !!! OK !!!" << std::endl;
                        }
                        
                    } else {
                        std::cout << "Take 1: Certificate not found." << std::endl;
                    }
                    i++;
                } else if(i == 2 && state == "Valid") {
                    limal::path::PathInfo certFile("./TestRepos/Test_CA1/newcerts/" +
                                                   certificateName + ".pem");
                    if(certFile.exists()) {

                        try {

                            ca.deleteCertificate(certificateName, false);
                        
                            certFile.stat();
                            if(!certFile.exists()) {
                                std::cout << "Take 2: Delete Certificate successfull." << std::endl;
                            } else {
                                std::cout << "Take 2: Delete Certificate failed." << std::endl;
                            }
                        } catch(limal::RuntimeException &e) {
                            std::cout << "Take 2: Delete Certificate failed. This is ok" << std::endl;
                        }
                    } else {
                        std::cout << "Take 2: Certificate not found." << std::endl;
                    }
                    
                    i++;
                } else {
                    continue;
                }
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
