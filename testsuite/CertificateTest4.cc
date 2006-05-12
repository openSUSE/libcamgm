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
using namespace limal;
using namespace limal::ca_mgm;
using namespace std;

int main()
{
	sleep( 2 );  // We have a request with the same name. So sleep 2 sec. to get a difference in the timestamp
	try
	{
		cout << "START" << endl;
        
		blocxx::StringArray cat;
		cat.push_back("FATAL");
		cat.push_back("ERROR");
		cat.push_back("INFO");
		//cat.push_back("DEBUG");

		// Logging
		LoggerRef l = limal::Logger::createCerrLogger(
		                                              "CertificateTest4",
		                                              LogAppender::ALL_COMPONENTS,
		                                              cat,
		                                              "%-5p %c - %m"
		                                              );
		limal::Logger::setDefaultLogger(l);
        
		CA ca("Test_CA1", "system", "./TestRepos/");
		RequestGenerationData rgd = ca.getRequestDefaults(E_Client_Req);
        
		// ------------------------ Set DN --------------------------------
        
		List<RDNObject> dnl = rgd.getSubjectDN().getDN();
		List<RDNObject>::iterator dnit;
        
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

		blocxx::String r = ca.createRequest("system", rgd, E_Client_Req);
        
		cout << "RETURN Request " << endl;

		// ------------------------ get issue defaults --------------------------------

		CertificateIssueData cid = ca.getIssueDefaults(E_Client_Cert);

		// ------------------------ create netscape extension -----------------------------

		cid.extensions().nsBaseUrl().setValue("http://www.my-company.com/");

		cid.extensions().nsRevocationUrl().setValue("http://www.my-company.com/revoke.pl");
		cid.extensions().nsCaRevocationUrl().setValue("http://www.my-company.com/CArevoke.pl");
		cid.extensions().nsRenewalUrl().setValue("http://www.my-company.com/renew.pl");
		cid.extensions().nsCaPolicyUrl().setValue("http://www.my-company.com/policy.html");
		cid.extensions().nsSslServerName().setValue("*.my-company.com");
		cid.extensions().nsComment().setValue("My Company Certificate");

		// ------------------------ create bit extension -----------------------------

		cid.extensions().keyUsage().setKeyUsage(KeyUsageExt::decipherOnly);
		cid.extensions().nsCertType().setNsCertType(NsCertTypeExt::objCA | 
		                                            NsCertTypeExt::emailCA |
		                                            NsCertTypeExt::sslCA);

		// ----------------- create basic constrains extension -----------------------

		cid.extensions().basicConstraints().setBasicConstraints(true, 3);

		// ----------------- create extended keyUsage extension ----------------------

		StringList sl;
		sl.push_back("2.3.4.5");
		sl.push_back("2.12.10.39");
		sl.push_back("codeSigning");
		sl.push_back("msCTLSign");
		sl.push_back("nsSGC");

		cid.extensions().extendedKeyUsage().setExtendedKeyUsage( sl );
        
		// ------------------------ create key identifier extension -----------------------------
        
		cid.extensions().subjectKeyIdentifier().setSubjectKeyIdentifier(true);
		cid.extensions().authorityKeyIdentifier().setKeyID(AuthorityKeyIdentifierGenerateExt::KeyID_always);
		cid.extensions().authorityKeyIdentifier().setIssuer(AuthorityKeyIdentifierGenerateExt::Issuer_always);

		// ------------------------ create alternative extension -----------------------------
        
		List<LiteralValue> list;
		list.push_back(LiteralValue("IP", "164.34.35.184"));
		list.push_back(LiteralValue("DNS", "ca.my-company.com"));
		list.push_back(LiteralValue("RID", "1.2.3.4"));
		list.push_back(LiteralValue("email", "me@my-company.com"));
		list.push_back(LiteralValue("URI", "http://www.my-company.com/"));
        
		cid.extensions().subjectAlternativeName().setCopyEmail(true);
		cid.extensions().subjectAlternativeName().setAlternativeNameList(list);
		cid.extensions().issuerAlternativeName().setCopyIssuer(true);
		cid.extensions().issuerAlternativeName().setAlternativeNameList(list);
        
		// ---------------- create authority information extension ------------------------
       
		List<AuthorityInformation> info;
		info.push_back(AuthorityInformation("OCSP", 
		                                    LiteralValue("URI", "http://www.my-company.com/ocsp.pl")));
		info.push_back(AuthorityInformation("caIssuers", 
		                                    LiteralValue("URI", "http://www.my-company.com/caIssuer.html")));
        
		cid.extensions().authorityInfoAccess().setAuthorityInformation(info);

		// ------------------------ create CRL dist point extension -----------------------

		List<LiteralValue> crldist;
		crldist.push_back(LiteralValue("URI", "ldap://ldap.my-company.com/?ou=PKI%2ddc=my-company%2ddc=com"));

		cid.extensions().crlDistributionPoints().setCRLDistributionPoints(crldist);

		// -------------------- create certificate policy extension -----------------------

		blocxx::List<CertificatePolicy> p;
		p.push_back(CertificatePolicy("1.12.35.1"));

		CertificatePolicy p2;
		p2.setPolicyIdentifier("1.3.6.8");
        
		StringList slp;
		slp.push_back("http://www.my-company.com/");
		slp.push_back("http://www2.my-company.com/");
		p2.setCpsURI(slp);

		List<Int32> num;
		num.push_back(1);
		num.push_back(5);
		num.push_back(8);

		UserNotice un;
		un.setExplicitText("This is the explicite Text");
		un.setOrganizationNotice("My Company", num);

		List<UserNotice> unl;
		unl.push_back(un);
		p2.setUserNoticeList(unl);
		p.push_back(p2);

		cid.extensions().certificatePolicies().setPolicies(p);
        
		//---------------------------------------------------------------------------------
        
		blocxx::String c = ca.issueCertificate(r, cid, E_CA_Cert);

		cout << "RETURN Certificate " << endl;

		path::PathInfo pi("./TestRepos/Test_CA1/newcerts/" + c + ".pem");
        
		cout << "Certificate exists: " << Bool(pi.exists()) << endl;

		CertificateData cd = ca.getCertificate(c);
        
		StringArray ret = cd.getExtensions().dump();
		StringArray::const_iterator it;
        
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
