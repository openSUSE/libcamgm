#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/ca-mgm/CA.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("CA1");


int main(int argc, char **argv)
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
                                                         "CA1",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        CA ca("ca1_test", "system", "./TestRepos/");
        
        RequestGenerationData rgd = ca.getRequestDefaults(CA_Req);
 
        StringArray a = rgd.verify();
        
        StringArray::const_iterator it = a.begin();
        for(; it != a.end(); ++it) {
            std::cout << (*it) << std::endl;
        }
       
        StringArray dump = rgd.dump();
        StringArray::const_iterator it2 = dump.begin();
        for(; it2 != dump.end(); ++it2) {
            if(!r.match(*it2)) {
                std::cout << (*it2) << std::endl;
            }
        }

        std::cout << "======================== getIssueDefaults =================" << std::endl;

        CertificateIssueData cid = ca.getIssueDefaults(CA_Cert);
 
        a = cid.verify();
        
        it = a.begin();
        for(; it != a.end(); ++it) {
            std::cout << (*it) << std::endl;
        }
       
        dump = cid.dump();
        it2 = dump.begin();
        for(; it2 != dump.end(); ++it2) {
            if(!r.match(*it2)) {
                std::cout << (*it2) << std::endl;
            }
        }

        std::cout << "======================== getCRLDefaults =================" << std::endl;

        CRLGenerationData cgd = ca.getCRLDefaults();
 
        a = cgd.verify();
        
        it = a.begin();
        for(; it != a.end(); ++it) {
            std::cout << (*it) << std::endl;
        }
       
        dump = cgd.dump();
        it2 = dump.begin();
        for(; it2 != dump.end(); ++it2) {
            if(!r.match(*it2)) {
                std::cout << (*it2) << std::endl;
            }
        }

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
