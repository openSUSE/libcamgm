#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/CA.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

// FIXME: need to be removed
#include <Utils.hpp>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace std;

int main(int argc, char **argv)
{
    if ( argc != 2 )
    {
        cerr << "Usage: CA7 <filepath>" << endl;
        exit( 1 );
    }

    // Logging
    boost::shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
    LogControl logger = LogControl::instance();
    logger.setLineFormater( formater );
    logger.setLogLevel( logger::E_DEBUG );
    logger.logToStdErr();

    std::string file = argv[ 1 ];

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
            std::string    line = str::getline( in );
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

            std::vector<std::string> a = Ncgd.verify();

            std::vector<std::string>::const_iterator it;
            for(it = a.begin(); it != a.end(); ++it)
            {
                cout << (*it) << endl;
            }

            cout << "============= Call Dump" << endl;
            PerlRegEx r("^!CHANGING DATA!.*$");

            std::vector<std::string> dump = Ncgd.dump();
            std::vector<std::string>::const_iterator it2;
            for(it2 = dump.begin(); it2 != dump.end(); ++it2)
            {
                if(!r.match(*it2))
                {
                    cout << (*it2) << endl;
                }
            }
        }
        catch(ca_mgm::Exception& e)
        {
            cerr << e << endl;
        }
    }

    cout << "DONE" << endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
