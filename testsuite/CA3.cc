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

// FIXME: need to be removed
#include <Utils.hpp>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main(int argc, char **argv)
{

    if ( argc != 2 )
    {
        cerr << "Usage: CA3 <filepath>" << endl;
        exit( 1 );
    }

    // Logging
    LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                  "CA3",
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
            blocxx::String    line = blocxx::String::getLine( in );
            if(line == "EOF") break;

            std::vector<blocxx::String> params = convStringArray(PerlRegEx("\\s").split(line));

            cout << "creating CA object" << endl;

            CA ca(params[0], "system", "./TestRepos/");

            CertificateIssueData cid;

            cout << "============= Test:" << params[0] << "=>" << params[1] << endl;

            if(params[1] == "CA_Cert")
            {
                cid = ca.getIssueDefaults(E_CA_Cert);
            }
            else if(params[1] == "Server_Cert")
            {
                cid = ca.getIssueDefaults(E_Server_Cert);
            }
            else if(params[1] == "Client_Cert")
            {
                cid = ca.getIssueDefaults(E_Client_Cert);
            }
            else
            {
                cout << "unknown parameter" << endl;
            }

            cout << "============= Call Verify" << endl;

            std::vector<blocxx::String> a = cid.verify();

            StringArray::const_iterator it;
            for(it = a.begin(); it != a.end(); ++it)
            {
                cout << (*it) << endl;
            }

            cout << "============= Call Dump" << endl;
            PerlRegEx r("^!CHANGING DATA!.*$");

            std::vector<blocxx::String> dump = cid.dump();

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
