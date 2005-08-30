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

limal::Logger logger("ParseRequestTest");


int main(int argc, char **argv)
{
    
    if ( argc != 2 ) {
        std::cerr << "Usage: ParseRequestTest <filepath>" << std::endl;
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
                                                     "ParseRequestTest",
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
            if(line == "EOF" || line.empty()) {
                break;
            }

            blocxx::StringArray params = blocxx::PerlRegEx("\\s").split(line);
            if(params.size() != 2) {
                break;
            }

            CA ca(params[0], "system", "./TestRepos/");
            
            std::cout << "Parse " << params[1] << " in " << params[0] << std::endl;

            RequestData cd = ca.getRequest(params[1]);

            blocxx::Array<blocxx::String> ret = cd.dump();

            blocxx::Array<blocxx::String>::const_iterator it = ret.begin();

            for(; it != ret.end(); ++it) {
                
                std::cout << (*it) << std::endl;
            }

            std::cout << "=================== call verify ======================" << std::endl;

            ret = cd.verify();
            it  = ret.begin();

            for(; it != ret.end(); ++it) {
                
                std::cout << "> " << (*it) << std::endl;
            }

        } catch(blocxx::Exception& e) {
            std::cerr << e << std::endl;
        }
    }
    
    std::cout << "DONE" << std::endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
