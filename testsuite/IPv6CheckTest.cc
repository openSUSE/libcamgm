#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/ValueCheck.hpp>
#include "Utils.hpp"

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
        logger.setLogLevel( logger::E_INFO );
        logger.logToStdErr();

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
    catch(ca_mgm::Exception& e)
    {
        cerr << e << endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
