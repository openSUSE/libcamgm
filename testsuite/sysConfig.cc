
#define LIMAL_LOGGER_LOGGROUP "parser"

#include <ca-mgm/String.hpp>
#include <ca-mgm/LogControl.hpp>
#include "INIParser/INIParser.hpp"

#include <iostream>
#include <fstream>
#include <unistd.h>

#include "TestLineFormater.hpp"

using namespace ca_mgm;
using namespace ca_mgm::INI;

void dumpTree(Section *section, int level = 0)
{
  std::string tab = "";
  for (int i = 0; i <= level; i++) tab += "  ";

  if (level == 0)
    INF << tab << std::endl;

  INF << tab << "SectionComment " << section->getComment() << std::endl;

  EntryMap eMap= section->getEntries();
  for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
  {
    Entry entry = i->second;
    INF << tab << "Comment " << i->first << " : " << entry.getComment() << std::endl;
    INF << tab << "Entry   " << i->first << " : " << entry.getValue() << std::endl;
  }

  SectionMap sMap = section->getSections();
  for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
  {
    Section sec = i->second;
    INF << tab << "Section " << i->first << std::endl;
    dumpTree (&sec, ++level);
  }
}

int main(int , char **)
{
  std::cout << "START" << std::endl;

  // Logging
  shared_ptr<LogControl::LineFormater> formater(new TestLineFormater());
  LogControl logger = LogControl::instance();
  logger.setLineFormater( formater );
  logger.setLogLevel( logger::E_DEBUG );
  logger.logToStdErr();

  // Initialize parser for testfile
  SysConfig parser;

  // Parsing input file
  std::string srcFile("iniParser/sysconfig.ini.test");
  std::string command = "/bin/cp iniParser/sysconfig.ini " + srcFile;
  system(command.c_str());
  parser.initFiles (srcFile);

  if (!parser.initMachine ())
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

  parser.iniFile.addValue ("DEFAULT_LANGUAGE2", "german");
  parser.iniFile.delEntry ("DEFAULT_LANGUAGE");
  parser.iniFile.setValue ("ENABLE_SUSECONFIG", "no");

  parser.write();

  // Re-reading testfile
  SysConfig testparser;
  testparser.initFiles (srcFile);

  if (!testparser.initMachine ())
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
