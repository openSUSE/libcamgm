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

int main()
{
    PerlRegEx r("^!CHANGING DATA!.*$");

    try
    {
        cout << "START" << endl;
        
        StringArray comp;
        comp.push_back("ca-mgm");
        comp.push_back("limal");
        
        // Logging
        
        LoggerRef l = limal::Logger::createCerrLogger(
                                                      "CA1",
                                                      comp,
                                                      LogAppender::ALL_CATEGORIES,
                                                      "%-5p %c - %m"
                                                      );

        limal::Logger::setDefaultLogger(l);
        
        CA ca("ca1_test", "system", "./TestRepos/");
        
        cout << "======================== getRequestDefaults =================" << endl;

        RequestGenerationData rgd = ca.getRequestDefaults(E_CA_Req);

        cout << "======================== call verify() =================" << endl;
 
        StringArray a = rgd.verify();
        
        StringArray::const_iterator it;
        
        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }
       
        cout << "======================== call dump() =================" << endl;

        StringArray dump = rgd.dump();
        StringArray::const_iterator it2;
        
        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
            }
        }

        cout << "======================== getIssueDefaults =================" << endl;

        CertificateIssueData cid = ca.getIssueDefaults(E_CA_Cert);
 
        cout << "======================== call verify() =================" << endl;

        a = cid.verify();
        
        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }
       
        cout << "======================== call dump() =================" << endl;

        dump = cid.dump();
        
        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
            }
        }

        cout << "======================== getCRLDefaults =================" << endl;

        CRLGenerationData cgd = ca.getCRLDefaults();
 
        cout << "======================== call verify() =================" << endl;
  
        a = cgd.verify();
        
        for(it = a.begin(); it != a.end(); ++it)
        {
            cout << (*it) << endl;
        }
       
        cout << "======================== call dump() =================" << endl;

        dump = cgd.dump();

        for(it2 = dump.begin(); it2 != dump.end(); ++it2)
        {
            if(!r.match(*it2))
            {
                cout << (*it2) << endl;
            }
        }

        cout << "DONE" << endl;
        
    }
    catch(Exception& e)
    {
        cerr << e << endl;
    }
    
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
