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

limal::Logger logger("ListCATreeTest");

int main()
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
                                                         "ListCATreeTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start CA Tree List ======================" << std::endl;

        blocxx::List<blocxx::List<blocxx::String> > tree = CA::getCATree("./TestRepos3/");

        blocxx::List<blocxx::List<blocxx::String> >::const_iterator it_ext = tree.begin();

        for(; it_ext != tree.end(); ++it_ext) {

            blocxx::List<blocxx::String>::const_iterator it_int = (*it_ext).begin();

            for(; it_int != (*it_ext).end(); ++it_int) {

                std::cout << *it_int << "  " ;
            }
            std::cout << std::endl;
        }
        std::cout << "=================== end CA Tree List ========================" << std::endl;

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
