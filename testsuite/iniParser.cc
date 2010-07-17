
#define LIMAL_LOGGER_LOGGROUP "parser"

#include <limal/String.hpp>
#include <limal/LogControl.hpp>
#include "INIParser/INIParser.hpp"
#include <limal/Exception.hpp>

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater.hpp"

using namespace ca_mgm::INI;
using namespace ca_mgm;

void addEntries(Section descSection, Section section)
{
  // Adding entries
  EntryMap eMap= descSection.getEntries();
  for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
  {
    Entry entry = i->second;

    if (!section.addEntry (i->first, entry.getValue(), entry.getComment()))
    {
      ERR << "Adding   " << i->first << " : " << entry.getValue() << std::endl;
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
      INF << "Creating Subsection  " << i->first << std::endl;

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
    INF << "Deleting Entry: " << i->first << std::endl;

    if (!section.delEntry (i->first))
    {
      ERR << "Deleting entry  " << i->first << std::endl;
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
      INF << "Deleting Section: " << i->first << std::endl;
      if (!section.delSection (i->first))
      {
        ERR << "Deleting section  " << i->first << std::endl;
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
    INF << "Searching for Entry: " << i->first << " Ignore case : " << entry.getValue() << std::endl;
    EntryMap eMap = section.selectEntries (i->first,
                                           entry.getValue() == "true" ? true : false);
    for (EntryMap::iterator i = eMap.begin();
    i != eMap.end(); i++)
    {
      Entry entry = i->second;
      INF << "  found " << i->first << " : "
      << entry.getValue() << std::endl;
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
    INF << "Searching for Section: " << i->first
    << " Ignore case : " << entry.getValue() << std::endl;
    SectionMap eMap = section.selectSections (i->first,
                                              entry.getValue()
                                              == "true" ? true : false);
    for (SectionMap::iterator i = eMap.begin();
    i != eMap.end(); i++)
    {
      INF << "  found " << i->first << std::endl;
    }
  }
}



void dumpTree(Section *section, int level = 0)
{
  std::string tab = "";
  for (int i = 0; i <= level; i++) tab += "  ";

  if (level == 0)
    INF << tab << std::endl;

  INF << tab <<
  "SectionComment " << section->getComment() << std::endl;

  EntryMap eMap= section->getEntries();
  for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
  {
    Entry entry = i->second;
    INF << tab <<
    "Comment " << i->first << " : " << entry.getComment() << std::endl;
    INF <<tab <<
    "Entry   " << i->first << " : " << entry.getValue() << std::endl;
  }

  SectionMap sMap = section->getSections();
  for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
  {
    Section sec = i->second;
    INF << tab << "Section " << i->first << std::endl;
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
  shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
  LogControl logger = LogControl::instance();
  logger.setLineFormater( formater );
  logger.setLogLevel( logger::E_DEBUG );
  logger.logToStdErr();

  // Loading description file
  INIParser descParser;
  std::vector<Options>  	options;
  std::vector<std::string> 		commentsDescr;
  std::vector<SectionDescr> 	sectionDescr;
  std::vector<EntryDescr> 	entryDescr;
  std::vector<IoPatternDescr> 	rewrites;
  std::string file = argv[ 1 ];
  std::cout << "== loading file : " << file << std::endl;

  descParser.initFiles (file);
  options.push_back (GLOBAL_VALUES);
  IoPatternDescr pattern = {"^[ \t]*([^=]*[^ \t=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" ,"%s=%s"};
  EntryDescr eDescr =  {pattern, "", "" ,false};
  entryDescr.push_back (eDescr);
  commentsDescr.push_back(std::string("^[ \t]*;.*"));

  IoPatternDescr patternBegin = {"[ \t]*\\+([A-Za-z0-9_]+)[ \t]*", "+%s"};
  IoPatternDescr patternEnd = {"[ \t]*\\-([A-Za-z0-9_]+)[ \t]*", "-%s"};
  SectionDescr sDescr =  {patternBegin, patternEnd , true };
  sectionDescr.push_back (sDescr);

  if (!descParser.initMachine (options, commentsDescr, sectionDescr,
    entryDescr, rewrites, "  "))
  {
    ERR << "Cannot initialize parser for configuration file " << file << std::endl;
    exit (1);
  }

  if (!descParser.parse ())
  {
    ERR << "Cannot parse configuration file " << file << std::endl;
    exit (1);
  }


  DBG << "Configuration file " << file << " parsed." << std::endl;
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
    #define COMPARE_OPTION(X) if (value == #X) options.push_back(X); else
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
    key += str::numstring(++counter);
  }

  counter = 1;
  key = "comment1";
  while (descParser.iniFile.contains (key) == VALUE)
  {
    commentsDescr.push_back (descParser.iniFile.getValue (key));
    key = "comment";
    key += str::numstring(++counter);
  }

  counter = 1;
  key = "match1";
  while (descParser.iniFile.contains (key) == VALUE)
  {
    std::string keyWrite = "write" + str::numstring(counter);
    IoPatternDescr pattern = {descParser.iniFile.getValue (key) ,
    descParser.iniFile.getValue (keyWrite)};
    EntryDescr eDescr =  {pattern, "", "" ,false};
    entryDescr.push_back (eDescr);
    key = "match";
    key += str::numstring(++counter);
  }

  counter = 1;
  key = "secBeginReg1";
  while (descParser.iniFile.contains (key) == VALUE)
  {
    std::string keyWrite = "secBeginWrite" + str::numstring(counter);
    IoPatternDescr patternBegin = {descParser.iniFile.getValue (key) ,
    descParser.iniFile.getValue (keyWrite)};
    key = "secEndReg" + str::numstring(counter);
    keyWrite = "secEndWrite" + str::numstring(counter);
    IoPatternDescr patternEnd = {descParser.iniFile.getValue (key),
    descParser.iniFile.getValue (keyWrite)};
    SectionDescr sDescr =  {patternBegin, patternEnd ,
    descParser.iniFile.contains (key) == VALUE };
    sectionDescr.push_back (sDescr);
    key = "secBeginReg";
    key += str::numstring(++counter);
  }

  // Parsing input file

  std::string srcFile = file + std::string("i.test");
  std::string command = "/bin/cp " + file + "i " + srcFile;
  system(command.c_str());
  parser.initFiles (srcFile);

  if (!parser.initMachine (options, commentsDescr, sectionDescr,
    entryDescr, rewrites, "  "))
  {
    ERR << "Cannot initialize parser for file " << srcFile << std::endl;
    exit (1);
  }

  if (!parser.parse ())
  {
    ERR << "Cannot parse file " << srcFile << std::endl;
    exit (1);
  }

  DBG << "file " << srcFile << " parsed." << std::endl;
  dumpTree(&(parser.iniFile));

  // Changing entries
  counter = 1;
  key = "add1";
  while (descParser.iniFile.contains (key) == SECTION)
  {
    Section section = descParser.iniFile.getSection (key);
    addEntries (section, parser.iniFile);
    key = "add";
    key += str::numstring(++counter);
  }

  // Deleting entries
  counter = 1;
  key = "delete1";
  while (descParser.iniFile.contains (key) == SECTION)
  {
    Section section = descParser.iniFile.getSection (key);
    deleteEntries (section, parser.iniFile);
    key = "delete";
    key += str::numstring(++counter);
  }

  // Searching entries
  counter = 1;
  key = "searchEntry1";
  while (descParser.iniFile.contains (key) == SECTION)
  {
    Section section = descParser.iniFile.getSection (key);
    searchEntries (section, parser.iniFile);
    key = "searchEntry";
    key += str::numstring(++counter);
  }

  // Searching sections
  counter = 1;
  key = "searchSection1";
  while (descParser.iniFile.contains (key) == SECTION)
  {
    Section section = descParser.iniFile.getSection (key);
    searchSections (section, parser.iniFile);
    key = "searchSection";
    key += str::numstring(++counter);
  }


  parser.write();

  // Re-reading testfile
  INIParser testparser;
  testparser.initFiles (srcFile);

  if (!testparser.initMachine (options, commentsDescr, sectionDescr,
    entryDescr, rewrites, "  "))
  {
    ERR << "Cannot initialize parser for file " << srcFile << std::endl;
    exit (1);
  }

  if (!testparser.parse ())
  {
    ERR << "Cannot parse file " << srcFile << std::endl;
    exit (1);
  }

  DBG << "file " << srcFile << " parsed AGAIN." << std::endl;
  dumpTree(&(testparser.iniFile));


  std::cout << "DONE" << std::endl;
  return 0;
}

/* vim: set ts=8 sts=8 sw=8 ai noet: */
