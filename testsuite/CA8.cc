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

limal::Logger logger("CA8");

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
                                                         "CA8",
                                                         E_ALL_LEVEL,
                                                         logAppender
                                                         ));
        limal::Logger::setDefaultLogger(appLogger);
        
        RequestGenerationData rgd = CA::getRootCARequestDefaults("./TestRepos/");
        CertificateIssueData cid  = CA::getRootCAIssueDefaults("./TestRepos/");
        
        blocxx::List<RDNObject> dnl = rgd.getSubject().getDN();
        blocxx::List<RDNObject>::iterator dnit = dnl.begin();
        for(; dnit != dnl.end(); ++dnit) {
            std::cout << "DN Key " << (*dnit).getType() << std::endl;
            if((*dnit).getType() == "countryName") {
                (*dnit).setRDNValue("DE");
            } else if((*dnit).getType() == "commonName") {
                (*dnit).setRDNValue("Test CA");
            } else if((*dnit).getType() == "emailAddress") {
                (*dnit).setRDNValue("suse@suse.de");
            }
        }
        
        DNObject dn(dnl);
        rgd.setSubject(dn);
        
        CA::createRootCA("Test_CA", "system", rgd, cid, "./TestRepos/");

        path::PathInfo iKey("./TestRepos/Test_CA/cacert.key");
        path::PathInfo iReq("./TestRepos/Test_CA/cacert.req");
        path::PathInfo iCrt("./TestRepos/Test_CA/cacert.pem");

        if(iKey.isFile()) {
            std::cout << iKey.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << iKey.size() << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.key is not a file" <<std::endl;
        }

        if(iReq.isFile()) {
            std::cout << iReq.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.req is not a file" <<std::endl;
        }

        if(iCrt.isFile()) {
            std::cout << iCrt.toString() << " IS FILE" <<std::endl;
            if(iKey.size() > 0) {
                std::cout << "Size is greater then 0" << std::endl;
            } else {
                std::cout << "ERROR Size is 0" << std::endl;
            }
        } else {
            std::cout << "ERROR ./TestRepos/Test_CA/cacert.pem is not a file" <<std::endl;
        }

        std::cout << "DONE" << std::endl;
    } catch(blocxx::Exception& e) {
        std::cerr << e << std::endl;
    }

    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
