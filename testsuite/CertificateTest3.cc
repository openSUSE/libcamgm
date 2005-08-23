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

extern "C" {
#include <EXTERN.h>
#include <perl.h>
}

EXTERN_C void xs_init (pTHX);
PerlInterpreter *my_perl;

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("CertificateTest3");

int main()
{
    char *embedding[] = { "", "-I../src/", "-MDynaLoader", "-MOPENSSL", "-MOPENSSL::CATools", "-e", 
                          "0" };
    
    PERL_SYS_INIT3(&argc,&argv,&env);
    my_perl = perl_alloc();
    perl_construct( my_perl );
    
    perl_parse(my_perl, xs_init, 7, embedding, NULL);
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    perl_run(my_perl);


    try {
        std::cout << "START" << std::endl;
        
        blocxx::StringArray cat;
        cat.push_back("FATAL");
        cat.push_back("ERROR");
        cat.push_back("INFO");
        //cat.push_back("DEBUG");

        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             cat,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "CertificateTest3",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        CA ca("Test_CA1", "system", "./TestRepos/");
        RequestGenerationData rgd = ca.getRequestDefaults(Client_Req);

        blocxx::List<RDNObject> dnl = rgd.getSubject().getDN();
        blocxx::List<RDNObject>::iterator dnit = dnl.begin();
        for(; dnit != dnl.end(); ++dnit) {
            std::cout << "DN Key " << (*dnit).getType() << std::endl;
            if((*dnit).getType() == "countryName") {
                (*dnit).setRDNValue("DE");
            } else if((*dnit).getType() == "commonName") {
                (*dnit).setRDNValue("Full Test Certificate");
            }
            else if((*dnit).getType() == "emailAddress") {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);

        blocxx::String r = ca.createRequest("system", rgd, Client_Req);
        
        std::cout << "RETURN Request " << std::endl;

        CertificateIssueData cid = ca.getIssueDefaults(Client_Cert);

        X509v3CertificateIssueExtensions ex = cid.getExtensions();

        NsBaseUrlExtension nsBaseUrl("http://www.my-company.com/");
        NsRevocationUrlExtension nsRevocationUrl("http://www.my-company.com/revoke.pl");
        NsCaRevocationUrlExtension nsCaRevocationUrl("http://www.my-company.com/CArevoke.pl");
        NsRenewalUrlExtension nsRenewalUrl("http://www.my-company.com/renew.pl");
        NsCaPolicyUrlExtension nsCaPolicyUrl("http://www.my-company.com/policy.html");
        NsSslServerNameExtension nsSslServerName("*.my-company.com");
        NsCommentExtension nsComment("My Company Certificate");

        KeyUsageExtension ku(KeyUsageExtension::decipherOnly);
        NsCertTypeExtension nsCertType(NsCertTypeExtension::objCA | 
                                       NsCertTypeExtension::emailCA |
                                       NsCertTypeExtension::sslCA);

        BasicConstraintsExtension basicConstraints(true, 3);
        StringList sl;
        sl.push_back("2.3.4.5");
        sl.push_back("2.12.10.39");

        ExtendedKeyUsageExtension extendedKeyUsage(ExtendedKeyUsageExtension::codeSigning |
                                                   ExtendedKeyUsageExtension::msCTLSign |
                                                   ExtendedKeyUsageExtension::nsSGC,
                                                   sl);
        SubjectKeyIdentifierExtension subjectKeyIdentifier(true);
        AuthorityKeyIdentifierGenerateExtension 
            authorityKeyIdentifier(
                                   AuthorityKeyIdentifierGenerateExtension::KeyID_always,
                                   AuthorityKeyIdentifierGenerateExtension::Issuer_always);
        
        blocxx::List<LiteralValue> list;
        list.push_back(LiteralValue("IP", "164.34.35.184"));
        list.push_back(LiteralValue("DNS", "ca.my-company.com"));
        list.push_back(LiteralValue("RID", "1.2.3.4"));
        list.push_back(LiteralValue("email", "me@my-company.com"));
        list.push_back(LiteralValue("URI", "http://www.my-company.com/"));
        
        SubjectAlternativeNameExtension subjectAlternativeName(true, list);
        IssuerAlternativeNameExtension issuerAlternativeName(true, list);

        AuthorityInfoAccessExtension authorityInfoAccess;
        blocxx::List<AuthorityInformation> info;
        info.push_back(AuthorityInformation("OCSP", 
                                            LiteralValue("URI", "http://www.my-company.com/ocsp.pl")));
        info.push_back(AuthorityInformation("caIssuers", 
                                            LiteralValue("URI", "http://www.my-company.com/caIssuer.html")));
        authorityInfoAccess.setAuthorityInformation(info);

        CRLDistributionPointsExtension crlDistributionPoints;
        blocxx::List<LiteralValue> crldist;
        crldist.push_back(LiteralValue("URI", "ldap://ldap.my-company.com/?ou=PKI%2ddc=my-company%2ddc=com"));
        crlDistributionPoints.setCRLDistributionPoints(crldist);

        blocxx::List<CertificatePolicy> p;
        p.push_back(CertificatePolicy("1.12.35.1"));
        CertificatePolicy p2;
        p2.setPolicyIdentifier("1.3.6.8");
        StringList slp;
        slp.push_back("http://www.my-company.com/");
        slp.push_back("http://www2.my-company.com/");
        p2.setCpsURI(slp);

        blocxx::List<blocxx::Int32> num;
        num.push_back(1);
        num.push_back(5);
        num.push_back(8);

        UserNotice un;
        un.setExplicitText("This is the explicite Text");
        un.setOrganizationNotice("My Company", num);

        blocxx::List<UserNotice> unl;
        unl.push_back(un);
        p2.setUserNoticeList(unl);
        p.push_back(p2);

        CertificatePoliciesExtension certificatePolicies(p);
        
        ex.setNsBaseUrl(nsBaseUrl);
        ex.setNsRevocationUrl(nsRevocationUrl);
        ex.setNsCaRevocationUrl(nsCaRevocationUrl);
        ex.setNsRenewalUrl(nsRenewalUrl);
        ex.setNsCaPolicyUrl(nsCaPolicyUrl);
        ex.setNsSslServerName(nsSslServerName);
        ex.setNsComment(nsComment);

        ex.setNsCertType(nsCertType);
        ex.setKeyUsage(ku);

        ex.setBasicConstraints(basicConstraints);
        ex.setExtendedKeyUsage(extendedKeyUsage);
        ex.setSubjectKeyIdentifier(subjectKeyIdentifier);
        ex.setAuthorityKeyIdentifier(authorityKeyIdentifier);
        ex.setSubjectAlternativeName(subjectAlternativeName);
        ex.setIssuerAlternativeName(issuerAlternativeName);
        ex.setAuthorityInfoAccess(authorityInfoAccess);
        ex.setCRLDistributionPoints(crlDistributionPoints);
        ex.setCertificatePolicies(certificatePolicies);

        cid.setExtensions(ex);
        
        blocxx::String c = ca.issueCertificate(r, cid, CA_Cert);

        std::cout << "RETURN Certificate " << std::endl;

        limal::path::PathInfo pi("./TestRepos/Test_CA1/newcerts/" + c + ".pem");
        
        std::cout << "Certificate exists: " << blocxx::Bool(pi.exists()) << std::endl;

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
