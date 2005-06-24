#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/String.hpp>
#include <limal/Logger.hpp>
#include <limal/ca-mgm/CAConfig.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::CA_MGM_NAMESPACE;

limal::Logger logger("CAConfig");


int main(int argc, char **argv)
{
    std::cout << "START" << std::endl;

    // Logging
    blocxx::LogAppenderRef	logAppender(new CerrAppender(
					 LogAppender::ALL_COMPONENTS,
					LogAppender::ALL_CATEGORIES,
					// category component - message
					"%-5p %c - %m"
					 ));
    blocxx::LoggerRef	appLogger(new AppenderLogger(
					"CAConfig",
					E_ALL_LEVEL,
					logAppender
					));
    limal::Logger::setDefaultLogger(appLogger);

    CAConfig *config = new CAConfig("openssl.cnf.tmpl");
    CAConfig *configNew = config->clone("openssl.cnf.tmpl.test");
    
    LIMAL_SLOG(limal::Logger("ca-mgm"),
	       "DEBUG", "file openssl.cnf.tmpl.test parsed.");
    
    configNew->setValue ("v3_req", "basicConstraints", "CA:TRUE");
    configNew->deleteValue ("v3_req", "keyUsage");

    CAConfig *configDump = new CAConfig("openssl.cnf.tmpl.test");
    configDump->dump();

    delete (config);
    delete (configNew);
    delete (configDump);

    std::cout << "DONE" << std::endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
