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

limal::Logger logger("VerifyTest");

int main(int argc, char **argv)
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
                                                         "VerifyTest",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        std::cout << "=================== start Verify Test ======================" << std::endl;
        {
            PerlRegEx r1("revoked");

            CA ca("Test_CA2", "system", "./TestRepos/");

            CRLGenerationData cgd = ca.getCRLDefaults();

            ca.createCRL(cgd);

            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getCertificateList();
            
            blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >::const_iterator it = ret.begin();

            for(; it != ret.end(); ++it) {
                
                blocxx::String name = (*(*it).find("certificate")).second;
                blocxx::String serial = (*(*it).find("serial")).second;
                
                try {

                    ca.verifyCertificate( name );
                    
                    std::cout << serial << ": Verify success" << std::endl;
                    
                } catch(limal::RuntimeException &e) {
                    if(r1.match(e.what())) {
                        std::cout << serial << ": Verify failed: Found revoked certificate" << std::endl;
                    } else {
                        std::cout << serial << ": Verify failed: unknown reason" << std::endl;
                    }
                }
            }
        }

        std::cout << "=================== end List tests ========================" << std::endl;
        
        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
