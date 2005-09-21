#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/DateTime.hpp>
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

limal::Logger logger("ListTest");

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
                                                         "ListTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start getRequestList ======================" << std::endl;
        {
            CA ca("Test_CA2", "system", "./TestRepos/");

            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getRequestList();
            
            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >::const_iterator it = ret.begin();

            for(; it != ret.end(); ++it) {

                blocxx::Map<blocxx::String, blocxx::String>::const_iterator it2 = (*it).begin();

                std::cout << "New Entry" << std::endl;

                for(; it2 != (*it).end(); ++it2) {

                    if((*it2).first == "date")
                    {
                        PerlRegEx r("^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)\\s(\\d\\d):(\\d\\d):(\\d\\d)");
                        StringArray sa = r.capture( (*it2).second );

                        if(sa.size() == 7)
                        {
                            blocxx::DateTime dt( sa[1].toInt(), sa[2].toInt(), sa[3].toInt(),
                                                 sa[4].toInt(), sa[5].toInt(), sa[6].toInt() );
                            std::cout << (*it2).first << " = " <<
                                dt.toString("%Y-%m-%d %H:%M:%S UTC", DateTime::E_UTC_TIME) << std::endl;
                        }
                        else
                        {
                            std::cout << (*it2).first << " = " << (*it2).second << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << (*it2).first << " = " << (*it2).second << std::endl;
                    }

                }
            }

            std::cout << "getRequestList successfully executed" << std::endl;

        }
        std::cout << "=================== start getCertificateList ==================" << std::endl;
        {
            CA ca2("Test_CA2", "system", "./TestRepos/");
            
            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > ret;
            ret = ca2.getCertificateList();
            
            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >::const_iterator it = ret.begin();

            for(; it != ret.end(); ++it) {

                blocxx::Map<blocxx::String, blocxx::String>::const_iterator it2 = (*it).begin();

                std::cout << "New Entry" << std::endl;

                for(; it2 != (*it).end(); ++it2) {

                    std::cout << (*it2).first << " = " << (*it2).second << std::endl;

                }
            }

            std::cout << "getCertificateList successfully executed" << std::endl;

        }

        std::cout << "=================== end List tests ========================" << std::endl;
        
        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
