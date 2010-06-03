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
#include  <blocxx/PosixRegEx.hpp>

using namespace blocxx;

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
Section::Section(const blocxx::IntrusiveReference<IniParser> &parser)
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
    m_path.append(key);

    StringArray path;
    StringList  valueList;
    
    valueList.clear();
    valueList.push_back(""); // Currently no comment will be
                             // generated for this section
    path.clear();
    path.append("section");
    path.appendArray (parentSection.m_path);
    path.append(key);    
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
    StringArray path;
    path.clear();
    stringList.clear();
    path.append("value");
    path.appendArray (m_path);
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
    StringArray path;
    path.clear();
    stringList.clear();
    path.append("section");
    path.appendArray (m_path);
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
    StringArray path;
    path.clear();
    stringList.clear();
    path.append("value");
    path.appendArray (m_path);
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
	path.append("section");
	path.appendArray (m_path);
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
std::list<blocxx::String> Section::getEntryKeys() const
{
    StringList entryKeys;
    StringList stringList;
    StringArray path;
    
    path.clear();
    stringList.clear();
    path.append("value");
    path.appendArray (m_path);
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
    StringArray path;
    
    path.clear();
    stringList.clear();
    path.append("value");
    path.appendArray (m_path);
    if (m_parser)
    {
	// Evaluate all keys
	m_parser->inifile.Dir (path, stringList);
	for (StringList::iterator it = stringList.begin();
	     it != stringList.end(); it++)
	{
	    //evaluate 
	    StringArray valuePath;
	    StringList  valueList;
	    Value	value("");
	    Comment     comment("");
	    
	    valuePath = path;
	    valueList.clear();
	    valuePath.append(*it);
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
	    valuePath.append("value_comment");
	    valuePath.appendArray (m_path);
	    valuePath.append(*it);
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
EntryMap Section::selectEntries(const blocxx::String &pattern,
				bool icase) const
{
    EntryMap entryMap = getEntries();
    blocxx::PosixRegEx reg(pattern, REG_EXTENDED | (icase ? REG_ICASE : 0));
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

    StringArray path;
    path.clear();
    path.append("value");
    path.appendArray (m_path);
    path.append(key);
    return m_parser->inifile.Delete (path)==0 ? true:false ;
}


// -------------------------------------------------------------------
bool Section::addValue(const Key &key, const Value &value)
{
    StringArray valuePath;
    StringList  valueList;
    
    valueList.clear();
    valueList.push_back(value);
    valuePath.clear();
    valuePath.append("value");
    valuePath.appendArray (m_path);
    valuePath.append(key);    
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

    StringArray valuePath;
    StringList  valueList;
    
    valueList.clear();
    valueList.push_back(entry.getComment());
    valuePath.clear();
    valuePath.append("value_comment");
    valuePath.appendArray (m_path);
    valuePath.append(key);    
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
std::list<blocxx::String> Section::getSectionKeys() const
{
    StringList sectionList;
    StringList stringList;
    StringArray path;
    
    path.clear();
    stringList.clear();
    path.append("section");
    path.appendArray (m_path);
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
    StringArray path;
    
    path.clear();
    stringList.clear();
    path.append("section");
    path.appendArray (m_path);
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
	    section.m_path.append (*it);
	    sectionMap.insert (SectionMap::value_type(*it,section));
	}
    }

    return sectionMap;
}


// -------------------------------------------------------------------
SectionMap Section::selectSections(const blocxx::String &pattern,
				   bool icase) const
{
    SectionMap sectionMap = getSections();
    blocxx::PosixRegEx reg(pattern, REG_EXTENDED | (icase ? REG_ICASE : 0));
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
	section.m_path.append (key);	
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

    StringArray path;
    path.clear();
    path.append("section");
    path.appendArray (m_path);
    path.append(key);    

    return m_parser->inifile.Delete (path) == 0 ? true:false;
}


// -------------------------------------------------------------------
bool Section::setComment( const Comment &comment)
{
    StringArray valuePath;
    StringList  valueList;
    
    valueList.clear();
    valueList.push_back(comment);
    valuePath.clear();
    valuePath.append("section_comment");
    valuePath.appendArray (m_path);
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
    StringArray valuePath;
    StringList  valueList;
    Comment comment;

    if (m_path.size() <= 0)
    {
	// there is no comment on top level section available
	return comment;
    }
 
    valuePath.clear();
    valueList.clear();
    valuePath.append("section_comment");
    valuePath.appendArray (m_path);
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
    if (parser->isStarted())
	parser->write();    
}


// -------------------------------------------------------------------
void INIParser::initFiles (const String &filename)
{
    parser->initFiles (filename.c_str());    
}
    
// -------------------------------------------------------------------
void INIParser::initFiles (const blocxx::StringArray &fileList )
{
    parser->initFiles(fileList);    
}

// -------------------------------------------------------------------
bool INIParser::initMachine (const blocxx::Array<Options> &options,
			     const blocxx::StringArray &commentsDescr,
			     const blocxx::Array<SectionDescr> &sectionDescr,
			     const blocxx::Array<EntryDescr> &entryDescr,
			     const blocxx::Array<IoPatternDescr> &rewrites,
			     const blocxx::String &subident)
{

    // Resetting flags; set to "is init"
    parser->reset();
    // options
    StringArray opt;
    opt.clear();
    for (unsigned int i = 0;i<options.size();i++)
    {
	switch (options[i])
	{
	    case IGNOMR_CASE_REGEXPS:
		opt.append ("ignore_case_regexps");
		break;
	    case IGNORE_CASE:
		opt.append ("ignore_case");
		break;
	    case FIRST_UPPER:
		opt.append ("first_upper");
		break;
	    case PREFER_UPPERCASE:
		opt.append ("prefer_uppercase");
		break;
	    case LINE_CAN_CONTINUE:
		opt.append ("line_can_continue");
		break;
	    case NO_NESTED_SECTIONS:
		opt.append ("no_nested_sections");
		break;
	    case GLOBAL_VALUES:
		opt.append ("global_values");
		break;
	    case REPEAT_NAMES:
		opt.append ("repeat_names");		
		break;
	    case COMMENTS_LAST:
		opt.append ("comments_last");		
		break;
	    case JOIN_MULTILINE:
		opt.append ("join_multiline");		
		break;
	    case NO_FINALCOMMENT_KILL:
		opt.append ("no_finalcomment_kill");		
		break;
	    case READ_ONLY:
		opt.append ("read_only");		
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
    blocxx::Array<Options>  		options;
    blocxx::StringArray 		commentsDescr;
    blocxx::Array<SectionDescr> 	sectionDescr;
    blocxx::Array<EntryDescr> 		entryDescr;
    blocxx::Array<IoPatternDescr> 	rewrites;

    options.append (GLOBAL_VALUES);
    options.append (LINE_CAN_CONTINUE);
    options.append (COMMENTS_LAST);
    options.append (JOIN_MULTILINE);

    commentsDescr.append("^[ \t]*#.*$");
    commentsDescr.append("#.*");
    commentsDescr.append("^[ \t]*$");

    IoPatternDescr pattern = { "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)\"", "%s=\"%s\""};
    EntryDescr eDescr =  {pattern, "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)", "([^\"]*)\"" , true};    
    entryDescr.append (eDescr);

    IoPatternDescr pattern2 = {"([a-zA-Z0-9_]+)[ \t]*=[ \t]*([^\"]*[^ \t\"]|)[ \t]*$", "%s=\"%s\""};
    EntryDescr eDescr2 =  {pattern2, "", "" , false};
    entryDescr.append (eDescr2);

    IoPatternDescr pattern3 = {"^[ \t]*([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)'", "%s='%s'" };
    EntryDescr eDescr3 =  {pattern3, "([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)", "([^']*)'" , true};
    entryDescr.append (eDescr3);        

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
