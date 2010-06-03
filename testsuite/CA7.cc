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
        cerr << "Usage: CA7 <filepath>" << endl;
        exit( 1 );
    }
    
    StringArray comp;
    comp.push_back("ca-mgm");
    comp.push_back("limal");

    // Logging
    LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                  "CA7",
                                                  comp,
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
            blocxx::String    line = blocxx::String::getLine( in );
            if(line == "EOF") break;

            cout << "creating CA object" << endl;
            
            CA ca(line, "system", "./TestRepos/");
            
            CRLGenerationData cgd;
            
            cout << "============= Test:" << line  << endl;
            
            cout << "============= read" << endl; 

            cgd = ca.getCRLDefaults();

            cout << "============= write back unchanged" << endl; 

            ca.setCRLDefaults(cgd);

            cout << "============= re-read" << endl; 

            CRLGenerationData Ncgd;
            Ncgd = ca.getCRLDefaults();

            cout << "============= Call Verify" << endl; 

            StringArray a = Ncgd.verify();
            
            StringArray::const_iterator it;
            for(it = a.begin(); it != a.end(); ++it)
            {
                cout << (*it) << endl;
            }
       
            cout << "============= Call Dump" << endl; 
            PerlRegEx r("^!CHANGING DATA!.*$");

            StringArray dump = Ncgd.dump();
            StringArray::const_iterator it2;
            for(it2 = dump.begin(); it2 != dump.end(); ++it2)
            {
                if(!r.match(*it2))
                {
                    cout << (*it2) << endl;
                }
            }            
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
