#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>

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

		blocxx::StringArray cat;
		cat.push_back("FATAL");
		cat.push_back("ERROR");
		cat.push_back("INFO");
		//cat.push_back("DEBUG");

		// Logging
		LoggerRef l = ca_mgm::Logger::createCerrLogger(
		                                              "CRLTest",
		                                              LogAppender::ALL_COMPONENTS,
		                                              cat,
		                                              "%-5p %c - %m"
		                                              );
		ca_mgm::Logger::setDefaultLogger(l);

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

		StringArray ret = cd.getExtensions().dump();
		StringArray::const_iterator it;
		
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
