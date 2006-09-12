#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main()
{
    try
    {
        cout << "START" << endl;
        
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        cat.push_back("DEBUG");

        StringArray comp;
        comp.push_back("ca-mgm");
        comp.push_back("limal");

        // Logging
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "VerifyTest",
                                                      comp,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        limal::Logger::setDefaultLogger(l);
        
        cout << "=================== start Verify Test ======================" << endl;
        {
            PerlRegEx r1("revoked");
            PerlRegEx r2("expired");

            CA ca("Test_CA2", "system", "./TestRepos/");

            CRLGenerationData cgd = ca.getCRLDefaults();

            ca.createCRL(cgd);

            Array<Map<blocxx::String, blocxx::String> > ret;
            ret = ca.getCertificateList();
            
            Array<Map<blocxx::String, blocxx::String> >::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {               
                blocxx::String name = (*(*it).find("certificate")).second;
                blocxx::String serial = (*(*it).find("serial")).second;
                
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
