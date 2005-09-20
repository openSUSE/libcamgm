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

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("CA9");

int main()
{
    PerlRegEx r("^!CHANGING DATA!.*$");

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
                                                         "CA9",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start CA List ======================" << std::endl;

        blocxx::Array<blocxx::String> list = CA::getCAList("./TestRepos/");

        blocxx::Array<blocxx::String>::const_iterator it = list.begin();

        for(; it != list.end(); ++it) {
            std::cout << *it << std::endl;
        }
        std::cout << "=================== end CA List ========================" << std::endl;

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
