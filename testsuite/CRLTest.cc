#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/Exception.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>

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

		CA ca("Test_CA1", "system", "./TestRepos/");
		CRLGenerationData cgd = ca.getCRLDefaults();

		cgd.extensions().authorityKeyIdentifier().setKeyID(AuthorityKeyIdentifierGenerateExt::KeyID_always);
		cgd.extensions().authorityKeyIdentifier().setIssuer(AuthorityKeyIdentifierGenerateExt::Issuer_always);

		std::list<LiteralValue> list;
		list.push_back(LiteralValue("email", "me@my-company.com"));
		list.push_back(LiteralValue("URI", "http://www.my-company.com/"));

		cgd.extensions().issuerAlternativeName().setCopyIssuer(true);
		cgd.extensions().issuerAlternativeName().setAlternativeNameList(list);

		ca.createCRL(cgd);

		path::PathInfo pi2("./TestRepos/Test_CA1/crl/crl.pem");
		if(pi2.size() > 0)
		{
			cout << "CRL file available and greater then 0" << endl;
		}

		CRLData cd = ca.getCRL();

		std::vector<std::string> ret = cd.getExtensions().dump();
		std::vector<std::string>::const_iterator it;

		for(it = ret.begin(); it != ret.end(); ++it)
		{
			cout << (*it) << endl;
		}

		cout << "DONE" << endl;
	}
	catch(Exception& e)
	{
		cerr << e << endl;
	}

	return 0;
}
