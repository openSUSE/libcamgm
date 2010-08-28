/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             core library                             |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       INIParser.cpp

  Author:     Stefan Schubert,
  Maintainer: Stefan Schubert

/-*/
/**
 * @brief Common parser of INI files
 */

#include "INIParser/IniParser.h"
#include "INIParser/IniFile.h"
#include "INIParser/INIParser.hpp"
#include  <ca-mgm/PosixRegEx.hpp>

#include "Utils.hpp"

// ===================================================================
namespace LIMAL_NAMESPACE
{
namespace INI  // INI_NAMESPACE (incl. version?)
{

// ===================================================================
Entry::Entry()
    : m_value(), m_comment()
{
}


// -------------------------------------------------------------------
Entry::Entry(const Entry &entry)
    :  m_value(entry.m_value), m_comment(entry.m_comment)
{
}


// -------------------------------------------------------------------
Entry::Entry(const Value &value)
    : m_value(value)
{
}


// -------------------------------------------------------------------
Entry::Entry(const Value &value, const Comment &comment)
    : m_value(value), m_comment(comment)
{
}


// -------------------------------------------------------------------
Entry::~Entry()
{
}


// -------------------------------------------------------------------
Value
Entry::getValue() const
{
    return m_value;
}


// -------------------------------------------------------------------
Comment
Entry::getComment() const
{
    return m_comment;
}


// -------------------------------------------------------------------
void
Entry::setValue(const Value &value)
{
    m_value = value;
}


// -------------------------------------------------------------------
void
Entry::setComment(const Comment &comment)
{
    m_comment = comment;
}



// ===================================================================

Section::Section()
    : m_path()
    , m_parser()
{}

// -------------------------------------------------------------------
Section::Section(IniParser *parser)
    : m_path()
    , m_parser(parser)
{
}

// -------------------------------------------------------------------
Section::Section(const Section      &section)
    : m_path(section.m_path),
      m_parser(section.m_parser)
{
}

// -------------------------------------------------------------------
Section&
Section::operator=(const Section      &section)
{
    m_path = section.m_path;
    m_parser = section.m_parser;
    return *this;
}

// -------------------------------------------------------------------
Section::Section(const Key &key, const Section &parentSection)
    : m_path(parentSection.m_path),
      m_parser(parentSection.m_parser)
{
    m_path.push_back(key);

    std::vector<std::string> path;
    StringList  valueList;

    valueList.clear();
    valueList.push_back(""); // Currently no comment will be
                             // generated for this section
    path.clear();
    path.push_back("section");
    appendArray (path, parentSection.m_path);
    path.push_back(key);
    if (m_parser)
    {
	m_parser->inifile.Write (path,
					 valueList,
					 m_parser->HaveRewrites ());
    }
}


// -------------------------------------------------------------------
Section::~Section()
{
}


// -------------------------------------------------------------------
EntrySize Section::entrySize() const
{
    StringList stringList;
    std::vector<std::string> path;
    path.clear();
    stringList.clear();
    path.push_back("value");
    appendArray (path, m_path);
    if (m_parser)
    {
	m_parser->inifile.Dir (path, stringList);
    }
    return stringList.size();
}

// -------------------------------------------------------------------
EntrySize Section::sectionSize() const
{
    StringList stringList;
    std::vector<std::string> path;
    path.clear();
    stringList.clear();
    path.push_back("section");
    appendArray (path, m_path);
    if (m_parser)
    {
	m_parser->inifile.Dir (path, stringList);
    }
    return stringList.size();
}


// -------------------------------------------------------------------
bool Section::empty() const
{
    if (entrySize () + sectionSize() > 0)
    {
	return true;
    }
    else
    {
	return false;
    }
}


// -------------------------------------------------------------------
IniType Section::contains(const Key &key) const
{
    IniType ret = NO;
    StringList stringList;
    std::vector<std::string> path;
    path.clear();
    stringList.clear();
    path.push_back("value");
    appendArray (path, m_path);
    if (m_parser)
    {
	m_parser->inifile.Dir (path, stringList);
        StringList::const_iterator it;
        for(it = stringList.begin(); it != stringList.end(); ++it)
        {
          if( key == *it)
            ret = VALUE;
        }
	path.clear();
	stringList.clear();
	path.push_back("section");
	appendArray (path, m_path);
	m_parser->inifile.Dir (path, stringList);
        for(it = stringList.begin(); it != stringList.end(); ++it)
        {
          if( key == *it)
          {
            if (ret == VALUE)
            {
                ret = VALUEandSECTION;
            }
            else
            {
                ret = SECTION;
            }
         }
       }
    }

    return ret;
}

// -------------------------------------------------------------------
std::list<std::string> Section::getEntryKeys() const
{
    StringList entryKeys;
    StringList stringList;
    std::vector<std::string> path;

    path.clear();
    stringList.clear();
    path.push_back("value");
    appendArray (path, m_path);
    if (m_parser)
    {
	// Evaluate all keys
	m_parser->inifile.Dir (path, stringList);
	for (StringList::iterator it = stringList.begin();
	     it != stringList.end(); it++)
	{
	    entryKeys.push_back(*it);
	}
    }

    return entryKeys;
}


// -------------------------------------------------------------------
EntryMap Section::getEntries() const
{
    EntryMap entrymap;
    StringList stringList;
    std::vector<std::string> path;

    path.clear();
    stringList.clear();
    path.push_back("value");
    appendArray (path, m_path);
    if (m_parser)
    {
	// Evaluate all keys
	m_parser->inifile.Dir (path, stringList);
	for (StringList::iterator it = stringList.begin();
	     it != stringList.end(); it++)
	{
	    //evaluate
	    std::vector<std::string> valuePath;
	    StringList  valueList;
	    Value	value("");
	    Comment     comment("");

	    valuePath = path;
	    valueList.clear();
	    valuePath.push_back(*it);
	    if (!m_parser->inifile.Read (valuePath,
						valueList,
						m_parser->HaveRewrites ())&&
		valueList.size() >= 1)
	    {
		// only the first element; no list
		value = *(valueList.begin());
	    }
	    valuePath.clear();
	    valueList.clear();
	    valuePath.push_back("value_comment");
	    appendArray (valuePath, m_path);
	    valuePath.push_back(*it);
	    if (!m_parser->inifile.Read (valuePath,
						valueList,
						m_parser->HaveRewrites ()) &&
		valueList.size() >= 1)
	    {
		// only the first element; no list
		comment = *(valueList.begin());
	    }
	    Entry entry (value,comment);
	    entrymap.insert (EntryMap::value_type(*it,entry));
	}
    }

    return entrymap;
}

// -------------------------------------------------------------------
EntryMap Section::selectEntries(const std::string &pattern,
				bool icase) const
{
    EntryMap entryMap = getEntries();
    PosixRegEx reg(pattern, REG_EXTENDED | (icase ? REG_ICASE : 0));
    EntryMap ret;

    for (EntryMap::iterator it = entryMap.begin(); it !=entryMap.end(); it++ )
    {
	if( reg.match(it->first) )
	{
	    ret.insert (EntryMap::value_type(it->first,it->second));
	}
    }

    return ret;
}


// -------------------------------------------------------------------
Value Section::getValue(const Key &key, const Value &defaultValue) const
{
    EntryMap entryMap = getEntries();
    EntryMap::iterator it = entryMap.find(key);

    if (it != entryMap.end())
    {
	Entry entry = it->second;
	return entry.getValue();
    }
    else
    {
	return defaultValue;
    }
}


// -------------------------------------------------------------------
Entry Section::getEntry(const Key &key, const Entry &defaultEntry) const
{
    EntryMap entryMap = getEntries();
    EntryMap::iterator it = entryMap.find(key);

    if (it != entryMap.end())
    {
	return it->second;
    }
    else
    {
	return defaultEntry;
    }
}

// -------------------------------------------------------------------
bool Section::delEntry(const Key &key)
{
    if (!m_parser)
    {
	return false;
    }

    std::vector<std::string> path;
    path.clear();
    path.push_back("value");
    appendArray (path, m_path);
    path.push_back(key);
    return m_parser->inifile.Delete (path)==0 ? true:false ;
}


// -------------------------------------------------------------------
bool Section::addValue(const Key &key, const Value &value)
{
    std::vector<std::string> valuePath;
    StringList  valueList;

    valueList.clear();
    valueList.push_back(value);
    valuePath.clear();
    valuePath.push_back("value");
    appendArray (valuePath, m_path);
    valuePath.push_back(key);
    if (m_parser)
    {
	return m_parser->inifile.Write (valuePath,
						valueList,
						m_parser->HaveRewrites ())==0 ? true:false;
    }

    return false;
}


// -------------------------------------------------------------------
bool Section::addEntry(const Key &key, const Entry &entry)
{
    bool ok = false;
    // adding value
    ok = addValue (key, entry.getValue());

    std::vector<std::string> valuePath;
    StringList  valueList;

    valueList.clear();
    valueList.push_back(entry.getComment());
    valuePath.clear();
    valuePath.push_back("value_comment");
    appendArray (valuePath, m_path);
    valuePath.push_back(key);
    if (ok && m_parser)
    {
	return m_parser->inifile.Write (valuePath,
						valueList,
						m_parser->HaveRewrites ()) == 0 ? true:false;
    }

    return false;
}


// -------------------------------------------------------------------
bool Section::addEntry(const Key &key,
		       const Value &value,
		       const Comment &comment)
{
    return addEntry (key, Entry (value, comment));
}


// -------------------------------------------------------------------
bool Section::setValue(const Key &key, const Value &value)
{
    return addValue (key, value);
}


// -------------------------------------------------------------------
bool Section::setEntry(const Key &key, const Entry &entry)
{
    return addEntry (key,entry);
}


// -------------------------------------------------------------------
bool Section::setEntry(const Key &key,
		       const Value &value,
		       const Comment &comment)
{
    return addEntry (key, value, comment);
}

// -------------------------------------------------------------------
std::list<std::string> Section::getSectionKeys() const
{
    StringList sectionList;
    StringList stringList;
    std::vector<std::string> path;

    path.clear();
    stringList.clear();
    path.push_back("section");
    appendArray (path, m_path);
    if (m_parser)
    {
	// Evaluate all keys
	m_parser->inifile.Dir (path, stringList);
	for (StringList::iterator it = stringList.begin();
	     it != stringList.end(); it++)
	{
	    sectionList.push_back (*it);
	}
    }

    return sectionList;
}


// -------------------------------------------------------------------
SectionMap Section::getSections() const
{
    SectionMap sectionMap;
    StringList stringList;
    std::vector<std::string> path;

    path.clear();
    stringList.clear();
    path.push_back("section");
    appendArray (path, m_path);
    if (m_parser)
    {
	// Evaluate all keys
	m_parser->inifile.Dir (path, stringList);
	for (StringList::iterator it = stringList.begin();
	     it != stringList.end(); it++)
	{
	    //generate all sections
	    Section section(m_parser);
	    section.m_path = m_path;
	    section.m_path.push_back (*it);
	    sectionMap.insert (SectionMap::value_type(*it,section));
	}
    }

    return sectionMap;
}


// -------------------------------------------------------------------
SectionMap Section::selectSections(const std::string &pattern,
				   bool icase) const
{
    SectionMap sectionMap = getSections();
    PosixRegEx reg(pattern, REG_EXTENDED | (icase ? REG_ICASE : 0));
    SectionMap ret;

    for (SectionMap::iterator it = sectionMap.begin(); it !=sectionMap.end(); it++ )
    {
	if( reg.match(it->first) )
	{
	    ret.insert (SectionMap::value_type(it->first,it->second));
	}
    }

    return ret;
}


// -------------------------------------------------------------------
Section Section::getSection(const Key &key,
			    const Section *defaultSection) const
{
    if (contains(key) != NO)
    {
	Section section (m_parser);
        section.m_path = m_path;
	section.m_path.push_back (key);
	return section;
    }
    if (defaultSection != NULL)
    {
	return *defaultSection;
    }
    else
    {
	return *this;
    }
}


// -------------------------------------------------------------------
bool Section::delSection(const Key &key)
{
    if (!m_parser)
    {
	return false;
    }

    std::vector<std::string> path;
    path.clear();
    path.push_back("section");
    appendArray (path, m_path);
    path.push_back(key);

    return m_parser->inifile.Delete (path) == 0 ? true:false;
}


// -------------------------------------------------------------------
bool Section::setComment( const Comment &comment)
{
    std::vector<std::string> valuePath;
    StringList  valueList;

    valueList.clear();
    valueList.push_back(comment);
    valuePath.clear();
    valuePath.push_back("section_comment");
    appendArray (valuePath, m_path);
    if (m_parser)
    {
	return m_parser->inifile.Write (valuePath,
						valueList,
						m_parser->HaveRewrites ())==0 ? true:false;
    }

    return false;
}


// -------------------------------------------------------------------
Comment	Section::getComment()
{
    std::vector<std::string> valuePath;
    StringList  valueList;
    Comment comment;

    if (m_path.size() <= 0)
    {
	// there is no comment on top level section available
	return comment;
    }

    valuePath.clear();
    valueList.clear();
    valuePath.push_back("section_comment");
    appendArray (valuePath, m_path);
    if (m_parser && !m_parser->inifile.Read (valuePath,
					 valueList,
					 m_parser->HaveRewrites ()) &&
	valueList.size() >= 1)
    {
	// only the first element; no list
	comment = *(valueList.begin());
    }

    return comment;
}


// ===================================================================

// -------------------------------------------------------------------
INIParser::INIParser ()
    :	parser( new IniParser())
    , 	iniFile( parser)
{
}

// -------------------------------------------------------------------
INIParser::INIParser(const INIParser &iniParser)
    :	parser(iniParser.parser)
    ,	iniFile(iniParser.iniFile)
{
}

// -------------------------------------------------------------------
INIParser &
INIParser::operator=(const INIParser &iniParser)
{
	parser  = iniParser.parser;
	iniFile = iniParser.iniFile;
	return *this;
}

// -------------------------------------------------------------------
INIParser::~INIParser ()
{
  if (parser && parser->isStarted())
    parser->write();
}


// -------------------------------------------------------------------
void INIParser::initFiles (const std::string &filename)
{
    parser->initFiles (filename.c_str());
}

// -------------------------------------------------------------------
void INIParser::initFiles (const std::vector<std::string> &fileList )
{
    parser->initFiles(fileList);
}

// -------------------------------------------------------------------
bool INIParser::initMachine (const std::vector<Options> &options,
			     const std::vector<std::string> &commentsDescr,
			     const std::vector<SectionDescr> &sectionDescr,
			     const std::vector<EntryDescr> &entryDescr,
			     const std::vector<IoPatternDescr> &rewrites,
			     const std::string &subident)
{

    // Resetting flags; set to "is init"
    parser->reset();
    // options
    std::vector<std::string> opt;
    opt.clear();
    for (unsigned int i = 0;i<options.size();i++)
    {
	switch (options[i])
	{
	    case IGNOMR_CASE_REGEXPS:
		opt.push_back ("ignore_case_regexps");
		break;
	    case IGNORE_CASE:
		opt.push_back ("ignore_case");
		break;
	    case FIRST_UPPER:
		opt.push_back ("first_upper");
		break;
	    case PREFER_UPPERCASE:
		opt.push_back ("prefer_uppercase");
		break;
	    case LINE_CAN_CONTINUE:
		opt.push_back ("line_can_continue");
		break;
	    case NO_NESTED_SECTIONS:
		opt.push_back ("no_nested_sections");
		break;
	    case GLOBAL_VALUES:
		opt.push_back ("global_values");
		break;
	    case REPEAT_NAMES:
		opt.push_back ("repeat_names");
		break;
	    case COMMENTS_LAST:
		opt.push_back ("comments_last");
		break;
	    case JOIN_MULTILINE:
		opt.push_back ("join_multiline");
		break;
	    case NO_FINALCOMMENT_KILL:
		opt.push_back ("no_finalcomment_kill");
		break;
	    case READ_ONLY:
		opt.push_back ("read_only");
		break;
	}
    }
    parser->initOptions (opt);

    // comments
    parser->initComments( commentsDescr );

    // sections
    parser->initSection (sectionDescr);

    parser->initSubident (subident);

    // entries
    parser->initParam (entryDescr);

    // rewrite settings
    parser->initRewrite (rewrites);

    // commit initialization
    parser->initCommit();

    return parser->isStarted();
}

// -------------------------------------------------------------------
bool INIParser::isInit()
{
    return parser->isStarted();
}

// -------------------------------------------------------------------
bool INIParser::parse()
{
    return parser->parse () == 0;
}

// -------------------------------------------------------------------
void INIParser::UpdateIfModif ()
{
    parser->UpdateIfModif ();
}

// -------------------------------------------------------------------
bool INIParser::write ()
{
    return parser->write() == 0;
}


// ===================================================================

bool SysConfig::initMachine ()
{
    std::vector<Options>  		options;
    std::vector<std::string> 		commentsDescr;
    std::vector<SectionDescr> 	sectionDescr;
    std::vector<EntryDescr> 		entryDescr;
    std::vector<IoPatternDescr> 	rewrites;

    options.push_back (GLOBAL_VALUES);
    options.push_back (LINE_CAN_CONTINUE);
    options.push_back (COMMENTS_LAST);
    options.push_back (JOIN_MULTILINE);

    commentsDescr.push_back("^[ \t]*#.*$");
    commentsDescr.push_back("#.*");
    commentsDescr.push_back("^[ \t]*$");

    IoPatternDescr pattern = { "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)\"", "%s=\"%s\""};
    EntryDescr eDescr =  {pattern, "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)", "([^\"]*)\"" , true};
    entryDescr.push_back (eDescr);

    IoPatternDescr pattern2 = {"([a-zA-Z0-9_]+)[ \t]*=[ \t]*([^\"]*[^ \t\"]|)[ \t]*$", "%s=\"%s\""};
    EntryDescr eDescr2 =  {pattern2, "", "" , false};
    entryDescr.push_back (eDescr2);

    IoPatternDescr pattern3 = {"^[ \t]*([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)'", "%s='%s'" };
    EntryDescr eDescr3 =  {pattern3, "([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)", "([^']*)'" , true};
    entryDescr.push_back (eDescr3);

    if (!INIParser::initMachine (options, commentsDescr, sectionDescr,
				 entryDescr, rewrites))
    {
	return false;
    }

    return true;
}


// ===================================================================
}	// namespace INI
}	// namespace LIMAL_NAMESPACE
/* vim: set ts=8 sts=8 sw=8 ai noet: */
