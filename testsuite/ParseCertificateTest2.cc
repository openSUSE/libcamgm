#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main(int argc, char **argv)
{
    
    if ( argc != 2 )
    {
        cerr << "Usage: ParseCertificateTest2 <filepath>" << endl;
        exit( 1 );
    }
    
    // Logging
    LoggerRef l = limal::Logger::createCerrLogger(
                                                  "ParseCertificateTest2",
                                                  LogAppender::ALL_COMPONENTS,
                                                  LogAppender::ALL_CATEGORIES,
                                                  "%-5p %c - %m"
                                                  );
    limal::Logger::setDefaultLogger(l);
    
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
            
            cout << "Parse " << params[0] << " Format:" << params[1] <<endl;

            FormatType t = E_PEM;

            if(params[1] == "DER")
            	t = E_DER;
            
            CertificateData cd = LocalManagement::getCertificate(params[0], t);
            
            StringArray ret = cd.dump();
            StringArray::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {                
                cout << (*it) << endl;
            }

            cout << "=================== call verify ======================" << endl;

            ret = cd.verify();
            
            for(it  = ret.begin(); it != ret.end(); ++it)
            {  
                cout << "> " << (*it) << endl;
            }

            cout << cd.getCertificateAsText() << endl;
            cout << cd.getExtensionsAsText() << endl;
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
