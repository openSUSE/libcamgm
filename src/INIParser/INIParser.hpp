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

  File:       INIParser.hpp

  Author:   Petr Blahos <pblahos@suse.cz>
            Martin Vidner <mvidner@suse.cz>
            Michael Andres <ma@suse.de>
            Marius Tomaschewski <mt@suse.de>
            Stefan Schubert <schubi@suse.de>
              
  Maintainer: Stefan Schubert

/-*/
/**
 * @file   INIParser.hpp
 * @brief  INI parser.
 *
 * @todo FIXME
 */
#ifndef LIMAL_INI_PARSER_HPP
#define LIMAL_INI_PARSER_HPP

#include  <limal/ca-mgm/config.h>
#include  <blocxx/Map.hpp>
#include  <blocxx/List.hpp>
#include  <blocxx/Array.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/StringStream.hpp>
#include  <blocxx/IntrusiveReference.hpp>
#include  "INIParser/INIParserDescr.hpp"

namespace LIMAL_NAMESPACE
{

/**
 * @brief The LiMaL INI parser namespace.
 */
namespace INI  // INI_NAMESPACE (incl. version?)
{

    

/**
 * @brief INI keyword string
 */
typedef blocxx::String		Key;


/**
 * @brief INI value string
 */
typedef blocxx::String		Value;


/**
 * @brief INI comment string array
 */    
typedef blocxx::String		Comment;
    

/**
 * @brief INI value entry class
 */
class Entry
{
public:
	Entry();
	Entry(const Entry &entry);
	Entry(const Value &value);
	Entry(const Value &value, const Comment &comment);
	~Entry();

	Value		getValue() const;
	Comment		getComment() const;

	void		setValue(const Value &value);
	void		setComment(const Comment &comment);
private:
	Value		m_value;
	Comment		m_comment;    

};

class Section;

typedef blocxx::Map<Key, Entry>		EntryMap;
typedef blocxx::Map<Key, Section>	SectionMap;    
typedef EntryMap::size_type		EntrySize;
typedef SectionMap::size_type		SectionSize;

class INIParser;
class IniParser;

/**
 * @brief INI section, describe a section ( include the "top level" section)
 */
class Section
{
private:
    friend class INIParser;
    /**
     * This constructor will only be used for creating the toplevel
     * section 
     */            
    Section(const blocxx::IntrusiveReference<IniParser> &parser);

public:
    Section();
    Section(const Section &section);
    Section & operator=(const Section &section);

    /**
     * Creating a subsection of an parent section. The main(toplevel) section
     * of an ini-file will be given by the parser ( member variable "inifile")
     * Use this constructor in order to add a NEW section.
     * @key of the section
     * @param description of the parent section
     */        
    Section(const Key &key, const Section &parentSection);

    ~Section();

    //----------------------------------------------------------------------------------------
    //
    // general functions
    //
    //----------------------------------------------------------------------------------------    

    /**
     * Get number of entries
     */    
    EntrySize	entrySize() const;

    /**
     * Get number of sub sections
     */        
    SectionSize	sectionSize() const;

    /**
     * Check, if the section is empty (no entry/section)
     * @return true or false
     */            
    bool	empty() const;

    /**
     * Check, if key is available in the section
     * @param   key of section/entry
     * @return  NO (not found), VALUE, SECTION
     */                
    IniType 	contains(const Key &key) const;

    /**
     * Changing a section comment
     * @param  comment
     * @return true if succeeded          
     */                                    
    bool	setComment(const Comment &comment);

    /**
     * Getting a section comment
     * @return comment
     */                                    
    Comment	getComment();


    //----------------------------------------------------------------------------------------
    //
    // Functions concerning entries of a section
    //
    //----------------------------------------------------------------------------------------

    /**
     * Get all entry keys of a section in the order like they
     * have been written to file.
     * @return blocxx::List<blocxx::String>
     */                        
    blocxx::List<blocxx::String> getEntryKeys() const;

    
    /**
     * Get all entries of a section
     * @return EntryMap ( key, entry )
     */                        
    EntryMap	getEntries() const;

    /**
     * Get all entries of a section which keys fit the given pattern
     * @param pattern string, ignore cases
     * @return EntryMap ( key, entry )
     */                        
    EntryMap	selectEntries(const blocxx::String &pattern,
			      bool icase = false) const;    

    /**
     * Get a value of an entry
     * @param  entry key, default value if the key has not been found
     * @return value
     */                            
    Value	getValue(const Key &key, const Value &defaultValue="") const;

    /**
     * Get the complete entry (value, comments,...)
     * @param  entry key, default entry if the key has not been found
     * @return entry object 
     */                                
    Entry	getEntry(const Key &key, const Entry &defaultEntry = Entry()) const;

    /**
     * Delete an entry
     * @param  entry key
     * @return true if succeeded
     */                                
    bool	delEntry(const Key &key);

    /**
     * Adding an value
     * @param  entry key, value
     * @return true if succeeded     
     */                                
    bool	addValue(const Key &key, const Value &value);
    
    /**
     * Adding an entry
     * @param  entry key, entry(value and comment)
     * @return true if succeeded     
     */                                    
    bool	addEntry(const Key &key, const Entry &entry);

    /**
     * Adding an entry
     * @param  entry key, value, comment
     * @return true if succeeded     
     */                                        
    bool	addEntry(const Key &key, const Value &value,
			 const Comment &comment);

    /**
     * Changing an value
     * @param  entry key, value
     * @return true if succeeded     
     */                                    
    bool	setValue(const Key &key, const Value &value);
    
    /**
     * Changing an entry
     * @param  entry key, value
     * @return true if succeeded     
     */                                        
    bool	setEntry(const Key &key, const Entry &entry);

    /**
     * Changing an entry
     * @param  entry key, value, comment
     * @return true if succeeded     
     */                                            
    bool	setEntry(const Key &key, const Value &value,
			 const Comment &comment);
    

    //----------------------------------------------------------------------------------------
    //
    // Functions concerning sub-sections of a section
    //
    //----------------------------------------------------------------------------------------

    /**
     * Get all section keys of a section in the order like they
     * have been written to file.
     * @return blocxx::List<blocxx::String>
     */                        
     blocxx::List<blocxx::String> getSectionKeys() const;

    
    /**
     * Get all sub-sections of a section
     * @return SectionMap (key, section)
     */                        
    SectionMap getSections() const;

    /**
     * Get all sub-sections of a section which keys fit the given pattern
     * @param pattern string, ignore cases
     * @return SectionMap (key, section)
     */                        
    SectionMap selectSections(const blocxx::String &pattern,
			      bool icase = false ) const;
    

    /**
     * Get the sub-section
     * @param  key, defaultSection returned if the key has not been found
     * @return section, defaultSection or the calling section itself
     *         if the defaultSection has not been defined.
     * @code
     *          if (section.getSection ("key-value") == section)
     *          {
     *               // error
     *          }
     * @endcode
     */                                
    Section	getSection(const Key &key,
			   const Section *defaultSection = NULL) const;

    /**
     * Delete a sub-section with all his entries
     * @param  key
     * @return true if succeeded
     */                                
    bool	delSection(const Key &key);


private:
    blocxx::StringArray m_path;
    blocxx::IntrusiveReference<IniParser> m_parser;
};


//----------------------------------------------------------------------------------------
//
// Parsing and writing descriptions/rules
//
//----------------------------------------------------------------------------------------


/**
 * @brief Options of the parser (INIParser).
 *
 * These options are available:
 *
 *          -  IGNOMR_CASE_REGEXPS
 *                ignore case in regexps
 *          -  IGNORE_CASE
 *                ignore case in keys and section names
 *          -  FIRST_UPPER
 *                if ignore case, outputs first upper and other lower
 *                If not first_upper, nor prefer_uppercase is set, keys 
 *                and values are saved in lower case.
 *          -  PREFER_UPPERCASE
 *                if ignore case, prefer upper case when saving
 *          -  LINE_CAN_CONTINUE
 *                if there is \ at the end of line, next line is appended to the current one
 *          -  NO_NESTED_SECTIONS
 *                nested sections are not allowed
 *          -  GLOBAL_VALUES
 *                values at the top level(not in section) are allowed
 *          -  REPEAT_NAMES
 *                more values or sections of the same name are allowed
 *          -  COMMENTS_LAST
 *                lines are parsed for comments after they are parsed for values
 *          -  JOIN_MULTILINE
 *                multiline values are connected into one
 *          -  NO_FINALCOMMENT_KILL
 *                do not kill empty lines at final comment at the end of top-level section
 *          -  READ_ONLY
 *                read-only mode
*/     

enum    Options { IGNOMR_CASE_REGEXPS,
		  IGNORE_CASE,
		  FIRST_UPPER,
		  PREFER_UPPERCASE,
		  LINE_CAN_CONTINUE,
		  NO_NESTED_SECTIONS,
		  GLOBAL_VALUES,
		  REPEAT_NAMES,
		  COMMENTS_LAST,
		  JOIN_MULTILINE,
		  NO_FINALCOMMENT_KILL,
		  READ_ONLY};


/**
 * @brief LiMaL Common parser of INI files
 * 
 * This class provides a set of functionality for reading and writing INI files. The parser can be configured
 * for almost each entry/value/comment format by using regular expressions.
 * The main tasks of this class are:
 *
 * - Describing the rules how to parse/write ini-files
 * - Parsing the ini-files
 * - Providing all parsed entries, sections and sub-sections
 * - Changing, adding and deleting entries/sections
 * - Writing changes to disk
 *
 * Here is an example for reading/writing a sysconfig file. Please have a look to the SysConfig class too.
 * The SysConfig has been derived from the INIParser class and is a wrapper over this description:
 *
 *    @code
 *   #include "INIParser/INIParser.hpp"
 *
 *   using namespace blocxx;
 *   using namespace ca_mgm;
 *   using namespace ca_mgm::INI;
 *
 *   blocxx::Array<Options>  		options; // Options like NO_NESTED_SECTIONS, LINE_CAN_CONTINUE, ...
 *   blocxx::StringArray 		commentsDescr; // Regular expression of the comments description
 *   blocxx::Array<SectionDescr> 	sectionDescr; // Regular expression of a section description
 *   blocxx::Array<EntryDescr> 		entryDescr; // Regular expressions for entries (keys/values).
 *   blocxx::Array<IoPatternDescr> 	rewrites; // rules for writing key/value
 *
 *   options.append (GLOBAL_VALUES); // Values at the top level(not in section) are allowed
 *   options.append (LINE_CAN_CONTINUE); // if there is \ at the end of line,
 *   options.append (COMMENTS_LAST); // Lines are parsed for comments after they are parsed for values 
 *
 *   // comment description
 *
 *   commentsDescr.append("^[ \t]*#.*$"); 
 *   commentsDescr.append("#.*");
 *   commentsDescr.append("^[ \t]*$");
 *
 *   // Entry (key/value) description
 *
 *   IoPatternDescr pattern = { "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)\"", "%s=\"%s\""};
 *   EntryDescr eDescr =  {pattern, "([a-zA-Z0-9_]+)[ \t]*=[ \t]*\"([^\"]*)", "([^\"]*)\"" , true};    
 *   entryDescr.append (eDescr);
 *
 *   IoPatternDescr pattern2 = {"([a-zA-Z0-9_]+)[ \t]*=[ \t]*([^\"]*[^ \t\"]|)[ \t]*$", "%s=\"%s\""};
 *   EntryDescr eDescr2 =  {pattern2, "", "" , false};
 *   entryDescr.append (eDescr2);
 *
 *   IoPatternDescr pattern3 = {"^[ \t]*([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)'", "%s='%s'" };
 *   EntryDescr eDescr3 =  {pattern3, "([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*=[ \t]*'([^']*)", "([^']*)'" , true};
 *   entryDescr.append (eDescr3);
 *
 *   INIParser descParser;        
 *
 *   // which file has to be parsed ?
 *
 *   descParser.initFiles ("/etc/sysconfig/mail");
 *
 *   // init the rest of parser
 *
 *   if (!INIParser::initMachine (options, commentsDescr, sectionDescr,
 *				 entryDescr, rewrites))
 *   {
 *	return "ERROR";
 *   }
 *
 *   // parsing file
 *
 *   if (!descParser.parse ())
 *   {
 *       return "ERROR";
 *   }
 *
 *   return descParser.iniFile.getValue("SMTPD_LISTEN_REMOTE");
 *   @endcode
 */
class INIParser
{
private:
    friend class Section;
    blocxx::IntrusiveReference<IniParser> parser;

public:

    /**
     * Toplevel ini section.
     */
    Section iniFile;

    INIParser ();
    INIParser (const INIParser &iniParser);
    INIParser & operator=(const INIParser &iniParser);

    virtual ~INIParser ();
    
    /**
     * Sets parser to single file mode and sets the file name to read.
     * @param fn file name of ini file
     */
    void initFiles (const blocxx::String &filename);
    
    /**
     * Sets parser to multiple file mode and sets the glob-expressions.
     * @param fileList list of glob-expressions
     */
    void initFiles (const blocxx::StringArray &fileList );
    
    /**
     * Sets flags and regular expressions.
     * @param options List of Options
     *             IGNOMR_CASE_REGEXPS
     *                ignore case in regexps
     *             IGNORE_CASE
     *                ignore case in keys and section names
     *             FIRST_UPPER
     *                if ignore case, outputs first upper and other lower
     *                If not first_upper, nor prefer_uppercase is set, keys 
     *                and values are saved in lower case.
     *             PREFER_UPPERCASE
     *                if ignore case, prefer upper case when saving
     *             LINE_CAN_CONTINUE
     *                if there is \ at the end of line, next line is appended to the current o
ne
     *             NO_NESTED_SECTIONS
     *                nested sections are not allowed
     *             GLOBAL_VALUES
     *                values at the top level(not in section) are allowed
     *             REPEAT_NAMES
     *                more values or sections of the same name are allowed
     *             COMMENTS_LAST
     *                lines are parsed for comments after they are parsed for values
     *             JOIN_MULTILINE
     *                multiline values are connected into one
     *             NO_FINALCOMMENT_KILL
     *                do not kill empty lines at final comment at the end of top-level section
     *             READ_ONLY
     *                read-only mode
     * @param commentsDescr Regular expression for comments.
     *             A list of regular expressions to check. Note that if you combine all expressions
     *             that identify string into one, you will have faster processing. If you allow
     *             comments not starting at the first colunm, you must add "[ \t]*" before comment
     *             regexp. If you want to allow only comments on single line, prepend ^ before regexp.
     * @param sectionDescr Regular expressions for sections.
     * @param entryDescr Regular expressions for entries (keys/values).
     * @param rewrites Regular expressions for rewrite rules. (multiple files)
     *             This list takes in effect only if multiple files are specified. There are rules
     *             for rewriting file name to section name and pattern back from the section name to file name.
     *             Example:
     *               "/etc/sysconfig/network/isdn/(*)$"  <-->  "/etc/sysconfig/network/isdn/%s"
     *               "/etc/sysconfig/network/modem/(*)$" <-->  "/etc/sysconfig/network/modem/%s"
     * @param subident This string will be added before each data line in subsections. If you want to
     *                 have indented subsections, use this. Example: " " "\t"
     * @return true if successful
     */
    virtual bool initMachine (const blocxx::Array<Options> &options,
		      const blocxx::StringArray &commentsDescr,
		      const blocxx::Array<SectionDescr> &sectionDescr,
		      const blocxx::Array<EntryDescr> &entryDescr,
		      const blocxx::Array<IoPatternDescr> &rewrites,
		      const blocxx::String &subident = "");

    /**
     * Check, if the parser has been already initialized
     * @return true if successful
     */
    bool isInit();

    /**
     * Parse the ini files. Parser must be initialized before this function
     * is called.
     * @return true if successful     
     */
    bool parse();
    
    /**
     * Check the ini files and in case some of them changed externally,
     * reload it.
     */
    void UpdateIfModif ();

    /**
     * Write changed ini files on disk
     * @return true if successful
     */
    bool write ();

};


/**
 * @brief Class for handling SysConfig files.
 *
 * It has been derived from the INIParser class
 */

class SysConfig : public INIParser
{
public:
    SysConfig() : INIParser() {};
    
    bool initMachine ();
    
};



}	// namespace INI
}	// namespace LIMAL_NAMESPACE

#endif  // LIMAL_INI_PARSER_HPP
/* vim: set ts=8 sts=8 sw=8 ai noet: */
