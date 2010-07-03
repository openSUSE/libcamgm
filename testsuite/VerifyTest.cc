#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;

using namespace ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;

        StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        cat.push_back("DEBUG");

        StringArray comp;
        comp.push_back("ca-mgm");
        comp.push_back("limal");

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "VerifyTest",
                                                      comp,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        ca_mgm::Logger::setDefaultLogger(l);

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
                catch(RuntimeException &e)
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
    catch(Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
