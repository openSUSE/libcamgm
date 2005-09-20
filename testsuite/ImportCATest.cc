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

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("ImportCATest");

int main(int argc, char **argv)
{
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

        try {

            CA::importCA("Test_CA3", 
                         LocalManagement::readFile("./TestRepos/importCATest.pem"),
                         LocalManagement::readFile("./TestRepos/importCATest.key"),
                         "", "./TestRepos/");

        } catch(limal::ValueException& e) {

            std::cout << "Got expected exception" << std::endl;
            std::cerr << e << std::endl;
            
            // this is a wanted exception
        }

        CA::importCA("Test_CA3",
                     LocalManagement::readFile("./TestRepos/importCATest.pem"),
                     LocalManagement::readFile("./TestRepos/importCATest.key"),
                     "tralla", "./TestRepos/");
        
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

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
