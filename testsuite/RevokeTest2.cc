#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PerlRegEx.hpp>
#include <limal/Logger.hpp>
#include <limal/PathInfo.hpp>
#include <limal/ca-mgm/CA.hpp>
#include <limal/ca-mgm/CRLReason.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::ca_mgm;

limal::Logger logger("RevokeTest2");

int main()
{

    try {
        std::cout << "START" << std::endl;
        
        blocxx::StringArray comp;
        comp.push_back("FATAL");
        comp.push_back("ERROR");
        comp.push_back("INFO");
        //comp.push_back("DEBUG");

        // Logging
        blocxx::LogAppenderRef	logAppender(new CerrAppender(
                                                             LogAppender::ALL_COMPONENTS,
                                                             comp,
                                                             // category component - message
                                                             "%-5p %c - %m"
                                                             ));
        blocxx::LoggerRef	appLogger(new AppenderLogger(
                                                         "RevokeTest2",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        CA ca("Test_CA1", "system", "./TestRepos/");
        RequestGenerationData rgd = ca.getRequestDefaults(Server_Req);

        blocxx::List<RDNObject> dnl = rgd.getSubject().getDN();
        blocxx::List<RDNObject>::iterator dnit = dnl.begin();
        for(; dnit != dnl.end(); ++dnit) {
            std::cout << "DN Key " << (*dnit).getType() << std::endl;
            if((*dnit).getType() == "countryName") {
                (*dnit).setRDNValue("DE");
            } else if((*dnit).getType() == "commonName") {
                (*dnit).setRDNValue("Test Certificate for revocation 2");
            }
            else if((*dnit).getType() == "emailAddress") {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);

        CertificateIssueData cid = ca.getIssueDefaults(Server_Cert);

        blocxx::String c = ca.createCertificate("system", rgd, cid, Server_Cert);

        std::cout << "RETURN Certificate " << std::endl;

        limal::path::PathInfo pi("./TestRepos/Test_CA1/newcerts/" + c + ".pem");
        
        std::cout << "Certificate exists: " << blocxx::Bool(pi.exists()) << std::endl;

        std::cout << "Try to revoke it" << std::endl;

        CRLReason reason(CRLReason::certificateHold);
        reason.setHoldInstruction("holdInstructionCallIssuer");

        ca.revokeCertificate(c, reason);

        blocxx::PerlRegEx r0("^([0-9a-fA-F]+):.*");
        blocxx::StringArray serial = r0.capture(c);

        std::ifstream in ("./TestRepos/Test_CA1/index.txt");

        blocxx::StringBuffer b;

        while(1) {
            blocxx::String line = b.getLine(in);

            blocxx::PerlRegEx r1("^R.+holdInstruction,holdInstructionCallIssuer\\t"+
                                 serial[1]+"\\t.*");

            if(r1.match(line)) {
                std::cout << "Found revoked certificate " << std::endl;
            }
            if(line.empty()) {
                break;
            }
        }

        std::cout << "Create a CRL" << std::endl;

        CRLGenerationData cgd = ca.getCRLDefaults();
        
        ca.createCRL(cgd);

        limal::path::PathInfo pi2("./TestRepos/Test_CA1/crl/crl.pem");
        if(pi2.size() > 0) {
            std::cout << "CRL file available and greater then 0" << std::endl;
        }

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
