/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                           |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       CAConfig.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include <fstream>
#include <iostream>
#include  <limal/ca-mgm/CAConfig.hpp>
#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;
using namespace limal::INI;
using namespace std;



CAConfig::CAConfig(const String &file)
    :srcFilename (file)
{
    parser = new INIParser ();

    blocxx::Array<Options>  		options;
    blocxx::StringArray 		commentsDescr;
    blocxx::Array<SectionDescr> 	sectionDescr;
    blocxx::Array<EntryDescr> 		entryDescr;
    blocxx::Array<IoPatternDescr> 	rewrites;

    options.append (NO_NESTED_SECTIONS);
    options.append (LINE_CAN_CONTINUE);

    commentsDescr.append ("^[ \t]*#.*$");
    commentsDescr.append ("#.*");
    commentsDescr.append ("^[ \t]*$");
    commentsDescr.append ("^[ \t]*;[^;]+.*$");    

    IoPatternDescr pattern1 = { "^[ \t]*([^=;]*[^ \t;=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" , "   %s = %s"};
    EntryDescr eDescr1 =  {pattern1, "", "" , false};    
    entryDescr.append (eDescr1);

    IoPatternDescr pattern2 = {"^[ \t]*;;[ \t]*([^=]*[^ \t=])[ \t]*=[ \t]*(.*[^ \t]|)[ \t]*$" , ";;   %s = %s"};
    EntryDescr eDescr2 =  {pattern2, "", "" , false};
    entryDescr.append (eDescr2);

    IoPatternDescr patternBegin1 = {"^[ \t]*\\[[ \t]*(.*[^ \t])[ \t]*\\][ \t]*", "[%s]"};
    IoPatternDescr patternBegin2 = {"^[ \t]*;;[ \t]*\\[[ \t]*(.*[^ \t])[ \t]*\\][ \t]*", ";; [%s]"};    
    IoPatternDescr patternEnd;
    SectionDescr sDescr1 =  {patternBegin1, patternEnd , false };
    sectionDescr.append (sDescr1);
    SectionDescr sDescr2 =  {patternBegin2, patternEnd , false };
    sectionDescr.append (sDescr2);   

    parser->initMachine (options, commentsDescr, sectionDescr, entryDescr, rewrites);
    parser->initFiles (file);
    parser->parse();
}

CAConfig::~CAConfig()
{
    delete(parser);
    parser = NULL;
}

void
CAConfig::dumpTree(Section *section, int level)
{
    String tab = "";
    for (int i = 0; i <= level; i++) tab += "  ";

    if (level == 0)
        LOGIT_INFO (tab);

    String sectionComment = section->getComment();
    if (sectionComment.length() > 0)
	LOGIT_INFO (tab <<
		    "SectionComment " << section->getComment());

    EntryMap eMap= section->getEntries();
    for (EntryMap::iterator i = eMap.begin(); i != eMap.end(); i++)
    {
        Entry entry = i->second;
	String comment = entry.getComment();
	if (comment.length() > 0)
	    LOGIT_INFO (tab <<
			"Comment " << i->first << " : " << entry.getComment());
        LOGIT_INFO (tab <<
		    "Entry   " << i->first << " : " << entry.getValue());
    }

    SectionMap sMap = section->getSections();
    for (SectionMap::iterator i = sMap.begin(); i != sMap.end(); i++)
    {
        Section sec = i->second;
        LOGIT_INFO (tab <<
		    "Section " << i->first);
        dumpTree (&sec, level+1);
    }
}


void
CAConfig::setValue(const String &section, const String &key, const String &value)
{
    if (parser->iniFile.contains (section) == NO)
    {
	// creating the section at first
	Section newSection (section, parser->iniFile);
	newSection.addValue(key, value);
    }
    else
    {
	// add entry only
	(parser->iniFile.getSection (section)).addValue(key, value);
    }
    // and save
    parser->write();
}

void
CAConfig::deleteValue(const String &section, const String &key)
{
    if (parser->iniFile.contains (section) == SECTION)
    {
	// delete entry
	(parser->iniFile.getSection (section)).delEntry (key);
	// and save
	parser->write();	
    }
}

blocxx::String
CAConfig::getValue(const String &section, const String &key) const
{
    if (parser->iniFile.contains (section) == SECTION)
    {
	// delete entry
	return (parser->iniFile.getSection (section)).getValue (key);
    }
    return "";
}

CAConfig*
CAConfig::clone(const String &file)
{
    ifstream in (srcFilename.c_str());
    ofstream out (file.c_str());

    if (!in)
    {
	LOGIT_ERROR ("Cannot open filename " << srcFilename );
	return NULL;
    }
    if (!out)
    {
	LOGIT_ERROR ("Cannot open filename " << file );
	return NULL;
    }	

    // coppying
    out << in.rdbuf();
    
    in.close();
    out.close();
	
    return new CAConfig (file);	
}

void
CAConfig::dump()
{
    dumpTree(&(parser->iniFile));
}    

// private

CAConfig::CAConfig()
{
}

CAConfig::CAConfig(const CAConfig&)
{
}

CAConfig&
CAConfig::operator=(const CAConfig&)
{
    return *this;
}


