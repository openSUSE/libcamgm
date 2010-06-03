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

using namespace ca_mgm::INI;

ca_mgm::Logger logger("parser");

void addEntries(Section descSection, Section section)
{
    // Adding entries
    EntryMap eMap= descSection.getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
	Entry entry = i->second;

	if (!section.addEntry (i->first, entry.getValue(), entry.getComment()))
	{
	    LIMAL_SLOG(logger, "ERROR",
			    "Adding   " << i->first
			    << " : " << entry.getValue());	    	    
	}
    }

    // Adding Entries and SubSections
    
    SectionMap sMap = descSection.getSections();
    for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
    {
	Section sec = i->second;

	// evaluate source section
	if (section.contains (i->first) != SECTION &&
	    section.contains (i->first) !=VALUEandSECTION )
	{
	    LIMAL_SLOG_INFO(logger, "Creating Subsection  " << i->first);
	    
	    Section newSection(i->first,section);
	    newSection.setComment (sec.getComment ());
	    
	    addEntries (sec, newSection );
	}
	else
	{
	    (section.getSection (i->first)).setComment (sec.getComment ());
	    addEntries (sec, section.getSection (i->first));
	}	    
    }
}

void deleteEntries(Section descSection, Section section)
{
    // Deleting entries

    EntryMap eMap= descSection.getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
	Entry entry = i->second;
	LIMAL_SLOG_INFO(logger, "Deleting Entry: " << i->first);
	
	if (!section.delEntry (i->first))
	{
	    LIMAL_SLOG(logger, "ERROR",
		       "Deleting entry  " << i->first);
	}
    }

    // Deleting sections if it has no entry
    
    SectionMap sMap = descSection.getSections();
    for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
    {
	Section sec = i->second;
	if ( sec.sectionSize() <= 0
	     && sec.entrySize() <= 0)
	{
	    // This section has no enties, so it will be deleted
	    LIMAL_SLOG_INFO(logger, "Deleting Section: " << i->first);	    
	    if (!section.delSection (i->first))
	    {
		LIMAL_SLOG(logger, "ERROR",
			   "Deleting section  " << i->first);
	    }
	}
	else
	{
	    // It has entries. So we look forward
    	    deleteEntries (sec, section.getSection (i->first));
	}	    
    }
}

void searchEntries(Section descSection, Section section)
{
    // searching entries

    EntryMap eMap= descSection.getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
	Entry entry = i->second;
	LIMAL_SLOG_INFO(logger, "Searching for Entry: " << i->first
			<< " Ignore case : " << entry.getValue());
	EntryMap eMap = section.selectEntries (i->first,
					       entry.getValue() == "true" ? true : false);
	for (EntryMap::iterator i = eMap.begin();
	     i != eMap.end(); i++)
	{
	    Entry entry = i->second;
	    LIMAL_SLOG_INFO(logger, "  found " << i->first << " : "
			    << entry.getValue());
	}
    }
}


void searchSections(Section descSection, Section section)
{
    // searching sections

    EntryMap eMap= descSection.getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
	Entry entry = i->second;
	LIMAL_SLOG_INFO(logger, "Searching for Section: " << i->first
			<< " Ignore case : " << entry.getValue());
	SectionMap eMap = section.selectSections (i->first,
						  entry.getValue()
						  == "true" ? true : false);
	for (SectionMap::iterator i = eMap.begin();
	     i != eMap.end(); i++)
	{
	    LIMAL_SLOG_INFO(logger, "  found " << i->first);
	}
    }
}



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
        if ( argc != 2 )
        {
             std::cerr << "Usage: iniParser <filepath>" << std::endl;
	     std::cout << "DONE" << std::endl;	     
	     exit( 1 );
        }

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
	ca_mgm::Logger::setDefaultLogger(appLogger);

	// Loading description file
	INIParser descParser;
	blocxx::Array<Options>  	options;
	blocxx::StringArray 		commentsDescr;
	blocxx::Array<SectionDescr> 	sectionDescr;
	blocxx::Array<EntryDescr> 	entryDescr;
	blocxx::Array<IoPatternDescr> 	rewrites;
        String file = argv[ 1 ];
	std::cout << "== loading file : " << file << std::endl;	

	descParser.initFiles (file);
	options.append (GLOBAL_VALUES);
	IoPatternDescr pattern = {"^[ \t]*([^=]*[^ \t=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" ,"%s=%s"};
	EntryDescr eDescr =  {pattern, "", "" ,false};
	entryDescr.append (eDescr);
	commentsDescr.append(String("^[ \t]*;.*"));

	IoPatternDescr patternBegin = {"[ \t]*\\+([A-Za-z0-9_]+)[ \t]*", "+%s"};
	IoPatternDescr patternEnd = {"[ \t]*\\-([A-Za-z0-9_]+)[ \t]*", "-%s"};	    
	SectionDescr sDescr =  {patternBegin, patternEnd , true };
	sectionDescr.append (sDescr);	

	if (!descParser.initMachine (options, commentsDescr, sectionDescr,
				     entryDescr, rewrites, "  "))
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot initialize parser for configuration file " << file);
	    exit (1);
	}

	if (!descParser.parse ())
	{
	    LIMAL_SLOG(logger, "ERROR", "Cannot parse configuration file " << file);
	    exit (1);
	}
	
	
	LIMAL_SLOG(logger, "DEBUG", "Configuration file " << file << " parsed.");
	dumpTree(&(descParser.iniFile));

	// Initialize parser for testfile
	INIParser parser;
	
	options.clear();
	commentsDescr.clear();
	sectionDescr.clear();
	entryDescr.clear();
	rewrites.clear();

	int counter = 1;
	Key key;
	Value value;	

	key = "option1";
	while (descParser.iniFile.contains (key) == VALUE)
	{
	    value = descParser.iniFile.getValue (key);
#define COMPARE_OPTION(X) if (value == #X) options.append(X); else 	    
	    COMPARE_OPTION(IGNOMR_CASE_REGEXPS);
	    COMPARE_OPTION(IGNORE_CASE);
	    COMPARE_OPTION(FIRST_UPPER);
	    COMPARE_OPTION(PREFER_UPPERCASE);
	    COMPARE_OPTION(LINE_CAN_CONTINUE);
	    COMPARE_OPTION(NO_NESTED_SECTIONS);
	    COMPARE_OPTION(GLOBAL_VALUES);
	    COMPARE_OPTION(REPEAT_NAMES);
	    COMPARE_OPTION(COMMENTS_LAST);
	    COMPARE_OPTION(JOIN_MULTILINE);
	    COMPARE_OPTION(NO_FINALCOMMENT_KILL);
	    COMPARE_OPTION(READ_ONLY);

	    key = "option";
	    key += String(++counter);
	}

	counter = 1;
	key = "comment1";
	while (descParser.iniFile.contains (key) == VALUE)
	{
	    commentsDescr.append (descParser.iniFile.getValue (key));
	    key = "comment";
	    key += String(++counter);
	}

	counter = 1;
	key = "match1";
	while (descParser.iniFile.contains (key) == VALUE)
	{
	    String keyWrite = "write" + String(counter);	    
	    IoPatternDescr pattern = {descParser.iniFile.getValue (key) , 
				      descParser.iniFile.getValue (keyWrite)};
	    EntryDescr eDescr =  {pattern, "", "" ,false};	    
	    entryDescr.append (eDescr);
	    key = "match";
	    key += String(++counter);
	}
	
	counter = 1;
	key = "secBeginReg1";
	while (descParser.iniFile.contains (key) == VALUE)
	{
	    String keyWrite = "secBeginWrite" + String(counter);	    
	    IoPatternDescr patternBegin = {descParser.iniFile.getValue (key) ,
					   descParser.iniFile.getValue (keyWrite)};
	    key = "secEndReg" + String(counter);
	    keyWrite = "secEndWrite" + String(counter);
	    IoPatternDescr patternEnd = {descParser.iniFile.getValue (key),
					 descParser.iniFile.getValue (keyWrite)};	    
	    SectionDescr sDescr =  {patternBegin, patternEnd ,
				    descParser.iniFile.contains (key) == VALUE };
	    sectionDescr.append (sDescr);
	    key = "secBeginReg";
	    key += String(++counter);
	}
	
        // Parsing input file
	
	String srcFile = file + String("i.test");
	String command = "/bin/cp " + file + "i " + srcFile;
	system(command.c_str());
	parser.initFiles (srcFile);
	
	if (!parser.initMachine (options, commentsDescr, sectionDescr,
				 entryDescr, rewrites, "  "))
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

	// Changing entries
	counter = 1;
	key = "add1";
	while (descParser.iniFile.contains (key) == SECTION)
	{
	    Section section = descParser.iniFile.getSection (key);
	    addEntries (section, parser.iniFile);
	    key = "add";
	    key += String(++counter);
	}

	// Deleting entries
	counter = 1;
	key = "delete1";
	while (descParser.iniFile.contains (key) == SECTION)
	{
	    Section section = descParser.iniFile.getSection (key);
	    deleteEntries (section, parser.iniFile);
	    key = "delete";
	    key += String(++counter);
	}

	// Searching entries
	counter = 1;
	key = "searchEntry1";
	while (descParser.iniFile.contains (key) == SECTION)
	{
	    Section section = descParser.iniFile.getSection (key);
	    searchEntries (section, parser.iniFile);
	    key = "searchEntry";
	    key += String(++counter);
	}

	// Searching sections
	counter = 1;
	key = "searchSection1";
	while (descParser.iniFile.contains (key) == SECTION)
	{
	    Section section = descParser.iniFile.getSection (key);
	    searchSections (section, parser.iniFile);
	    key = "searchSection";
	    key += String(++counter);
	}
	
	
	parser.write();

	// Re-reading testfile
	INIParser testparser;
	testparser.initFiles (srcFile);
	
	if (!testparser.initMachine (options, commentsDescr, sectionDescr,
				 entryDescr, rewrites, "  "))
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
