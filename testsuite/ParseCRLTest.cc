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

using namespace ca_mgm;
using namespace std;

int main(int argc, char **argv)
{
    
    if ( argc != 2 )
    {
        cerr << "Usage: ParseCRLTest <filepath>" << endl;
        exit( 1 );
    }
    
    // Logging
    LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                  "ParseCRLTest",
                                                  LogAppender::ALL_COMPONENTS,
                                                  LogAppender::ALL_CATEGORIES,
                                                  "%-5p %c - %m"
                                                  );
    ca_mgm::Logger::setDefaultLogger(l);
    
    blocxx::String file = argv[ 1 ];

    cout << "START" << endl;
    cout << "file: " << file << endl;

    ifstream in( file.c_str() );
    if ( in.fail() )
    {
        cerr << "Unable to load '" << file << "'" << endl;
        exit( 2 );
    }
    
    while( in )
    {        
        try
        {            
            blocxx::String     line = blocxx::String::getLine( in );
            if(line == "EOF" || line.empty()) break;

            StringArray params = blocxx::PerlRegEx("\\s").split(line);
            if(params.size() != 2) break;

            CA ca(params[1], "system", params[0]);
            
            cout << "Parse CRL in " << params[0] << "/" << params[1] << endl;

            CRLData crl = ca.getCRL();

            cout << "got the data" << endl;

            StringArray ret = crl.dump();

            cout << "dump the data" << endl;

            StringArray::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {               
                cout << (*it) << endl;
            }

            cout << "=================== call verify ======================" << endl;

            ret = crl.verify();
            
            for(it  = ret.begin(); it != ret.end(); ++it)
            {                
                cout << "> " << (*it) << endl;
            }

            cout << crl.getCRLAsText() << endl;
            cout << crl.getExtensionsAsText() << endl;
        }
        catch(Exception& e)
        {
            cerr << e << endl;
        }
    }
    
    cout << "DONE" << endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
