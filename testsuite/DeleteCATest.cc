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

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("DeleteCATest");

int main(int argc, char **argv)
{
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
                                                         "DeleteCATest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);

        // fake the index.txt
        limal::path::copyFile("./TestRepos/Test_CA1/index.txt", 
                              "./TestRepos/Test_CA/index.txt");

        try {

            CA::deleteCA("Test_CA", "system", false, "./TestRepos/");

        } catch(limal::RuntimeException& e) {

            std::cout << "Got expected exception" << std::endl;
            std::cerr << e << std::endl;
            
            // this is a wanted exception
        }

        CA::deleteCA("Test_CA", "system", true, "./TestRepos/");
        
        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
