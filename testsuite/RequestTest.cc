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

// FIXME: need to be removed
#include <Utils.hpp>

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
		                                              "RequestTest",
		                                              LogAppender::ALL_COMPONENTS,
		                                              cat,
		                                              "%-5p %c - %m"
		                                              );
		ca_mgm::Logger::setDefaultLogger(l);

		CA ca("Test_CA1", "system", "./TestRepos/");
		RequestGenerationData rgd = ca.getRequestDefaults(E_Server_Req);

		std::list<RDNObject> dnl = rgd.getSubjectDN().getDN();
		std::list<RDNObject>::iterator dnit;

		for(dnit = dnl.begin(); dnit != dnl.end(); ++dnit)
		{
			cout << "DN Key " << (*dnit).getType() << endl;

			if((*dnit).getType() == "countryName")
			{
				(*dnit).setRDNValue("DE");
			}
			else if((*dnit).getType() == "commonName")
			{
				(*dnit).setRDNValue("Test Request");
			}
			else if((*dnit).getType() == "emailAddress")
			{
				(*dnit).setRDNValue("suse@suse.de");
			}
		}

		DNObject dn(dnl);
		rgd.setSubjectDN(dn);

		// ------------------------ create netscape extension -----------------------------

		rgd.extensions().nsSslServerName().setValue("*.my-company.com");
		rgd.extensions().nsComment().setValue("My Company Certificate");

		// ------------------------ create bit extension -----------------------------

		rgd.extensions().keyUsage().setKeyUsage(KeyUsageExt::digitalSignature);
		rgd.extensions().nsCertType().setNsCertType(NsCertTypeExt::client |
		                                            NsCertTypeExt::email);

		rgd.extensions().basicConstraints().setPresent(false);

		StringList sl;
		sl.push_back("2.3.4.5");
		sl.push_back("2.12.10.39");

		rgd.extensions().extendedKeyUsage().setExtendedKeyUsage( sl );

		std::list<LiteralValue> list;
		list.push_back(LiteralValue("email", "me@my-company.com"));
		list.push_back(LiteralValue("URI", "http://www.my-company.com/"));

		rgd.extensions().subjectAlternativeName().setCopyEmail(true);
		rgd.extensions().subjectAlternativeName().setAlternativeNameList(list);


		blocxx::String r = ca.createRequest("system", rgd, E_Server_Req);

		cout << "RETURN Request " << endl;

		path::PathInfo pi("./TestRepos/Test_CA1/req/" + r + ".req");

		cout << "Request exists: " << Bool(pi.exists()) << endl;

		RequestData rd = ca.getRequest(r);

		std::vector<blocxx::String> ret = rd.getExtensions().dump();
		std::vector<blocxx::String>::const_iterator it;

		for(it = ret.begin(); it != ret.end(); ++it)
		{
			if((*it).startsWith("KeyID"))
			{
				cout << "found KeyID" << endl;
			}
			else
			{
				cout << (*it) << endl;
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
