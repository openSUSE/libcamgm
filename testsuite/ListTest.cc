#include <limal/String.hpp>
#include <limal/Date.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/LogControl.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

// FIXME: need to be removed
#include <Utils.hpp>

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

        cout << "=================== start getRequestList ======================" << endl;
        {
            CA ca("Test_CA2", "system", "./TestRepos/");

            std::vector< std::map<std::string, std::string> > ret;
            ret = ca.getRequestList();

            std::vector< std::map<std::string, std::string> >::const_iterator it;

            for(it = ret.begin(); it != ret.end(); ++it)
            {
                map<std::string, std::string>::const_iterator it2;

                cout << "New Entry" << endl;

                for(it2 = (*it).begin(); it2 != (*it).end(); ++it2)
                {
                    if((*it2).first == "date")
                    {
                      if(!((*it2).second.empty()) )
                      {
                        //cout << "DATE: " << (*it2).second << endl;
                        Date dt((*it2).second, "%Y-%m-%d %H:%M:%S", false);
                        cout << (*it2).first << " = " << dt.form("%Y-%m-%d %H:%M:%S", true) << " UTC"<< endl;
                      }
                    }
                    else
                    {
                        cout << (*it2).first << " = " << (*it2).second << endl;
                    }
                }
            }
            cout << "getRequestList successfully executed" << endl;
        }
        cout << "=================== start getCertificateList ==================" << endl;
        {
            CA ca2("Test_CA2", "system", "./TestRepos/");

            std::vector<map<std::string, std::string> > ret;
            ret = ca2.getCertificateList();

            std::vector<map<std::string, std::string> >::const_iterator it = ret.begin();

            for(it = ret.begin(); it != ret.end(); ++it)
            {
                map<std::string, std::string>::const_iterator it2;

                cout << "New Entry" << endl;

                for(it2 = (*it).begin(); it2 != (*it).end(); ++it2)
                {
                    cout << (*it2).first << " = " << (*it2).second << endl;
                }
            }
            cout << "getCertificateList successfully executed" << endl;
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
