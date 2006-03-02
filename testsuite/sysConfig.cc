#include <blocxx/Logger.hpp>
#include <blocxx/AppenderLogger.hpp>
#include <blocxx/CerrLogger.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/String.hpp>
#include <limal/Logger.hpp>
#include "INIParser/INIParser.hpp"

#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace blocxx;
using namespace limal;
using namespace limal::INI;

limal::Logger logger("parser");


void dumpTree(Section *section, int level = 0)
{
    String tab = "";
    for (int i = 0; i <= level; i++) tab += "  ";

    if (level == 0)
	LIMAL_SLOG_INFO(logger, tab);

    LIMAL_SLOG_INFO(logger, tab <<
		    "SectionComment " << section->getComment());	
    
    EntryMap eMap= section->getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
	Entry entry = i->second;
	LIMAL_SLOG_INFO(logger, tab <<
			"Comment " << i->first << " : " << entry.getComment());	
	LIMAL_SLOG_INFO(logger, tab <<
			"Entry   " << i->first << " : " << entry.getValue());
    }

    SectionMap sMap = section->getSections();
    for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
    {
	Section sec = i->second;
	LIMAL_SLOG_INFO(logger, tab <<
			"Section " << i->first);
	dumpTree (&sec, ++level);
    }
}

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
					"parser_test",
					E_ALL_LEVEL,
					logAppender
				));
	limal::Logger::setDefaultLogger(appLogger);


	// Initialize parser for testfile
	SysConfig parser;
	
        // Parsing input file
	String srcFile("iniParser/sysconfig.ini.test");
	String command = "/bin/cp iniParser/sysconfig.ini " + srcFile;
	system(command.c_str());
	parser.initFiles (srcFile);
	
	if (!parser.initMachine ())
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot initialize parser for file " << srcFile);
	    exit (1);
	}

	if (!parser.parse ())
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot parse file " << srcFile);
	    exit (1);
	}
	
	LIMAL_SLOG(logger, "DEBUG", "file " << srcFile << " parsed.");
	dumpTree(&(parser.iniFile));

	parser.iniFile.addValue ("DEFAULT_LANGUAGE2", "german");
	parser.iniFile.delEntry ("DEFAULT_LANGUAGE");
	parser.iniFile.setValue ("ENABLE_SUSECONFIG", "no");
	
	parser.write();

	// Re-reading testfile
	SysConfig testparser;
	testparser.initFiles (srcFile);
	
	if (!testparser.initMachine ())
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot initialize parser for file " << srcFile);
	    exit (1);
	}

	if (!testparser.parse ())
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot parse file " << srcFile);
	    exit (1);
	}
	
	LIMAL_SLOG(logger, "DEBUG", "file " << srcFile << " parsed AGAIN.");
	dumpTree(&(testparser.iniFile));

	std::cout << "DONE" << std::endl;
	return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
