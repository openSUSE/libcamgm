#include <ca-mgm/String.hpp>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/PathInfo.hpp>
#include <ca-mgm/CA.hpp>
#include <ca-mgm/Exception.hpp>

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
    boost::shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
    LogControl logger = LogControl::instance();
    logger.setLineFormater( formater );
    logger.setLogLevel( logger::E_INFO );
    logger.logToStdErr();

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
        rgd.setChallengePassword("secret");
        rgd.setUnstructuredName("this is an unstructured name");

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


		std::string r = ca.createRequest("system", rgd, E_Server_Req);

		cout << "RETURN Request " << endl;

		path::PathInfo pi("./TestRepos/Test_CA1/req/" + r + ".req");

		cout << "Request exists: " << str::toString(pi.exists()) << endl;

		RequestData rd = ca.getRequest(r);

		std::vector<std::string> ret = rd.dump();
		std::vector<std::string>::const_iterator it;

		for(it = ret.begin(); it != ret.end(); ++it)
		{
			if(str::startsWith((*it), "KeyID"))
			{
				cout << "found KeyID" << endl;
			}
            else if(str::startsWith((*it), "public Key"))
            {
                cout << "found PublicKey" << endl;
            }
            else if(str::startsWith((*it), "Signature"))
            {
                cout << "found Signature" << endl;
            }
			else
			{
				cout << (*it) << endl;
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
