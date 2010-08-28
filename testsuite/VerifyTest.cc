#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        // Logging
        shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
        LogControl logger = LogControl::instance();
        logger.setLineFormater( formater );
        logger.setLogLevel( logger::E_DEBUG );
        logger.logToStdErr();

        cout << "=================== start Verify Test ======================" << endl;
        {
            PerlRegEx r1("revoked");
            PerlRegEx r2("expired");

            CA ca("Test_CA2", "system", "./TestRepos/");

            CRLGenerationData cgd = ca.getCRLDefaults();

            ca.createCRL(cgd);

            std::vector<map<std::string, std::string> > ret;
            ret = ca.getCertificateList();

            std::vector<map<std::string, std::string> >::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {
                std::string name = (*(*it).find("certificate")).second;
                std::string serial = (*(*it).find("serial")).second;

                try
                {
                    ca.verifyCertificate( name );

                    cout << serial << ": Verify success" << endl;
                }
                catch(ca_mgm::RuntimeException &e)
                {
                	if(r1.match(e.what()))
                    {
                        cout << serial << ": Verify failed: Found revoked certificate" << endl;
                    }
                    else if(r2.match(e.what()))
                    {
                        cout << serial << ": Verify failed: Found expired certificate" << endl;
                    }
                    else
                    {
                        cout << serial << ": Verify failed: unknown reason" << endl;
                    }
                }
            }
        }
        cout << "=================== end List tests ========================" << endl;

        cout << "DONE" << endl;
    }
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
