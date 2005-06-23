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
    
    blocxx::String srcFile("openssl.cnf.tmpl.test");
    blocxx::String command = "/bin/cp openssl.cnf.tmpl " + srcFile;
    system(command.c_str());

    CAConfig *config = new CAConfig(srcFile);

    config->dump();
	
//    LIMAL_SLOG(logger, "DEBUG", "file " << srcFile << " parsed.");

//    LIMAL_SLOG(logger, "ERROR", "Cannot parse file " << srcFile);

    std::cout << "DONE" << std::endl;
    return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
