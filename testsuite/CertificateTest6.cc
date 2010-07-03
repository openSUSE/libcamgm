#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <limal/String.hpp>
#include <limal/PerlRegEx.hpp>
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
	sleep( 2 );  // We have a request with the same name. So sleep 2 sec. to get a difference in the timestamp
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
		                                              "CertificateTest6",
		                                              LogAppender::ALL_COMPONENTS,
		                                              cat,
		                                              "%-5p %c - %m"
		                                              );
		ca_mgm::Logger::setDefaultLogger(l);

		CA ca("Test_CA1", "system", "./TestRepos/");
		RequestGenerationData rgd = ca.getRequestDefaults(E_Client_Req);

		// ------------------------ Set DN --------------------------------

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
				(*dnit).setRDNValue("Full Test Certificate");
			}
			else if((*dnit).getType() == "emailAddress")
			{
				(*dnit).setRDNValue("suse@suse.de");
			}
		}

		DNObject dn(dnl);
		rgd.setSubjectDN(dn);

		// ------------------------ create request --------------------------------

		std::string r = ca.createRequest("system", rgd, E_Client_Req);

		cout << "RETURN Request " << endl;

		// ------------------------ get issue defaults --------------------------------

		CertificateIssueData cid = ca.getIssueDefaults(E_Client_Cert);

		// ------------------------ create bit extension -----------------------------

		cid.extensions().keyUsage().setKeyUsage(KeyUsageExt::decipherOnly);
		cid.extensions().nsCertType().setNsCertType(NsCertTypeExt::objCA |
		                                            NsCertTypeExt::emailCA |
		                                            NsCertTypeExt::sslCA);

		// ----------------- create basic constrains extension -----------------------

		cid.extensions().basicConstraints().setBasicConstraints(true, 3);

		// ------------------------ create alternative extension -----------------------------

		std::list<LiteralValue> list;
		list.push_back(LiteralValue("DNS", "ca.my-company.com"));
		list.push_back(LiteralValue("DNS", "127-55-2-80 ca.my-company.com"));
		list.push_back(LiteralValue("email", "me@my-company.com"));
		list.push_back(LiteralValue("1.3.6.1.4.1.311.20.2.3", "me@MY-COMPANY.COM"));   // ms_upn
		list.push_back(LiteralValue("1.3.6.1.5.2.2", "me@MY-COMPANY.COM"));            // krb5PrincipalName
		list.push_back(LiteralValue("1.3.6.1.4.1.311.20.2.3", "me/admin@MY-COMPANY.COM"));   // ms_upn
		list.push_back(LiteralValue("1.3.6.1.5.2.2", "me/admin@MY-COMPANY.COM"));            // krb5PrincipalName
		list.push_back(LiteralValue("IP", "2001:780:101:a00:211:11ff:fee6:a5af"));            // IPv6 address

		cid.extensions().subjectAlternativeName().setCopyEmail(true);
		cid.extensions().subjectAlternativeName().setAlternativeNameList(list);
		cid.extensions().issuerAlternativeName().setCopyIssuer(true);
		cid.extensions().issuerAlternativeName().setAlternativeNameList(list);


		std::string c = ca.issueCertificate(r, cid, E_CA_Cert);

		//sleep(10000);

		cout << "RETURN Certificate " << endl;

		path::PathInfo pi("./TestRepos/Test_CA1/newcerts/" + c + ".pem");

		cout << "Certificate exists: " << Bool(pi.exists()) << endl;

		CertificateData cd = ca.getCertificate(c);

		std::vector<std::string> ret = cd.getExtensions().dump();
		std::vector<std::string>::const_iterator it;

		for(it = ret.begin(); it != ret.end(); ++it)
		{
			if(str::startsWith((*it), "KeyID"))
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
