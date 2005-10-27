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
using namespace std;

int main(int argc, char **argv)
{
    if ( argc != 2 )
    {
        cerr << "Usage: CA6 <filepath>" << endl;
        exit( 1 );
    }

    StringArray comp;
    comp.push_back("ca-mgm");
    comp.push_back("limal");
    
    // Logging
    LoggerRef l = limal::Logger::createCerrLogger(
                                                  "CA6",
                                                  comp,
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
            blocxx::String    line = blocxx::String::getLine( in );
            if(line == "EOF") break;

            StringArray params = PerlRegEx("\\s").split(line);

            cout << "creating CA object" << endl;
            
            CA ca(params[0], "system", "./TestRepos/");
            
            CertificateIssueData cid;
    
            cout << "============= Test:" << params[0] << "=>" << params[1] << endl;
            
            Type t = E_CA_Req;
      
            if(params[1] == "CA_Cert")
            {
                t = E_CA_Cert;
            }
            else if(params[1] == "Server_Cert")
            {
                t = E_Server_Cert;
            }
            else if(params[1] == "Client_Cert")
            {
                t = E_Client_Cert;
            }
            else
            {
                cout << "unknown parameter" << endl;
                exit(1);
            }

            cout << "============= read" << endl; 
            
            cid = ca.getIssueDefaults(t);

            cout << "============= write back unchanged" << endl; 

            ca.setIssueDefaults(t, cid);
            
            cout << "============= re-read" << endl; 

            CertificateIssueData Ncid;
            Ncid = ca.getIssueDefaults(t);

            cout << "============= Call Verify" << endl; 

            StringArray a = Ncid.verify();
            
            StringArray::const_iterator it;
            for(it = a.begin(); it != a.end(); ++it)
            {
                cout << (*it) << endl;
            }
            
            cout << "============= Call Dump" << endl; 
            PerlRegEx r("^!CHANGING DATA!.*$");

            StringArray dump = Ncid.dump();
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
