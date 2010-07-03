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
#include <limal/ValueCheck.hpp>
#include "Utils.hpp"

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
        //cat.push_back("DEBUG");

        // Logging
        LoggerRef l = ca_mgm::Logger::createCerrLogger(
                                                      "IPv6CheckTest",
                                                      LogAppender::ALL_COMPONENTS,
                                                      cat,
                                                      "%-5p %c - %m"
                                                      );
        ca_mgm::Logger::setDefaultLogger(l);

        cout << "=================== start Test ======================" << endl;

		ValueCheck check = initIP6Check();

		std::vector<std::string> iparr ;
		iparr.push_back("2001:780:101:a00:211:11ff:fee6:a5af");
		iparr.push_back("fe80::211:11ff:fee6:a5af");
		iparr.push_back("2001::a5af");
		iparr.push_back("fe80:1:211:11ff:fee6::");

		iparr.push_back("fe80::211::fee6:a5af");
		iparr.push_back("2001:780:101:a00:211:11ff:fee6:a5af:afff");
		iparr.push_back("g001:780:101:a00:211:11ff:fee6:a5af");

		std::vector<std::string>::const_iterator ip_it;
		for(ip_it = iparr.begin(); ip_it != iparr.end(); ++ip_it)
		{
			//cout << "Explain: "<< check.explain(*ip_it) << endl;
			if(check.isValid((*ip_it)))
			{
				cout << *ip_it << " => is valid" << endl;
			}
			else
			{
				cout << *ip_it << " => is not valid" << endl;
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
