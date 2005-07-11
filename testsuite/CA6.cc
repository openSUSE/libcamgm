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

limal::Logger logger("CA6");


int main(int argc, char **argv)
{
    
    if ( argc != 2 ) {
        std::cerr << "Usage: CA6 <filepath>" << std::endl;
        exit( 1 );
    }
    
    // Logging
    blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                         LogAppender::ALL_COMPONENTS,
                                                         LogAppender::ALL_CATEGORIES,
                                                         // category component - message
                                                         "%-5p %c - %m"
                                                         ));
    blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                     "CA6",
                                                     E_ALL_LEVEL,
                                                     logAppender
                                                     ));
    limal::Logger::setDefaultLogger(appLogger);
    
    blocxx::String file = argv[ 1 ];
      
    
    std::cout << "START" << std::endl;
    std::cout << "file: " << file << std::endl;

    std::ifstream in( file.c_str() );
    if ( in.fail() ) {
        std::cerr << "Unable to load '" << file << "'" << std::endl;
        exit( 2 );
    }
    
    while( in ) {
        
        try {
            
            blocxx::String     line = blocxx::String::getLine( in );
            if(line == "EOF") {
                break;
            }
            blocxx::StringArray params = blocxx::PerlRegEx("\\s").split(line);

            std::cout << "creating CA object" << std::endl;
            
            CA ca(params[0], "system", "./TestRepos/");
            
            CertificateIssueData cid;
    
            std::cout << "============= Test:" << params[0] << "=>" << params[1] << std::endl;
            
            Type t = CA_Req;
      
            if(params[1] == "CA_Cert") {
                t = CA_Cert;
            } else if(params[1] == "Server_Cert") {
                t = Server_Cert;
            } else if(params[1] == "Client_Cert") {
                t = Client_Cert;
            } else {
                std::cout << "unknown parameter" << std::endl;
                exit(1);
            }


            std::cout << "============= read" << std::endl; 
            
            cid = ca.getIssueDefaults(t);

            std::cout << "============= write back unchanged" << std::endl; 

            ca.setIssueDefaults(t, cid);
            
            std::cout << "============= re-read" << std::endl; 

            CertificateIssueData Ncid;
            Ncid = ca.getIssueDefaults(t);

            std::cout << "============= Call Verify" << std::endl; 

            blocxx::StringArray a = Ncid.verify();
            
            blocxx::StringArray::const_iterator it = a.begin();
            for(; it != a.end(); ++it) {
                std::cout << (*it) << std::endl;
            }
            
            std::cout << "============= Call Dump" << std::endl; 
            PerlRegEx r("^!CHANGING DATA!.*$");

            blocxx::StringArray dump = Ncid.dump();
            blocxx::StringArray::const_iterator it2 = dump.begin();
            for(; it2 != dump.end(); ++it2) {
                if(!r.match(*it2)) {
                    std::cout << (*it2) << std::endl;
                }
            }
            
        } catch(blocxx::Exception& e) {
            std::cerr << e << std::endl;
        }
    }
    
    std::cout << "DONE" << std::endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
