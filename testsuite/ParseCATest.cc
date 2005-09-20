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

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("ParseCATest");

int main()
{

    try {
        std::cout << "START" << std::endl;
        
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        cat.push_back("DEBUG");

        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             cat,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "ParseCATest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start ParseCATest ======================" << std::endl;
        {
            CA ca("Test_CA2", "system", "./TestRepos/");

            CertificateData cd = ca.getCA();

            blocxx::Array<blocxx::String> ret = cd.dump();

            blocxx::Array<blocxx::String>::const_iterator it = ret.begin();

            for(; it != ret.end(); ++it) {
                
                std::cout << (*it) << std::endl;
            }

            std::cout << "=================== call verify ======================" << std::endl;

            ret = cd.verify();
            it  = ret.begin();

            for(; it != ret.end(); ++it) {
                
                std::cout << (*it) << std::endl;
            }
            
        }

        std::cout << "=================== end ParseCATest ========================" << std::endl;
        
        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
