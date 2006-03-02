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

  File:       INIParserDescr.hpp

  Author:     Stefan Schubert,
              Marius Tomaschewski
  Maintainer: Stefan Schubert

/-*/
/**
 * @file   INIParserDescr.hpp
 * @brief  INI parser configuraion structures.
 *
 * @todo FIXME
 */
#ifndef LIMAL_INI_PARSERDESCR_HPP
#define LIMAL_INI_PARSERDESCR_HPP

#include  <limal/config.h>
#include  <blocxx/String.hpp>

namespace LIMAL_NAMESPACE
{
namespace INI
{

enum    IniType { NO, VALUE, SECTION, VALUEandSECTION };

/**
 * @brief section/entry description of the INI parser
 *
 * Description of a section or an entry. An regular expression will be used for parsing
 * the section/entry. The second entry describes how to write the section/entry.
 * Eg. rx: "^ *Section +(.*)$", out: "Section %s"
 */
struct IoPatternDescr
{
    /**    
     * Reading description; 
     * An extended regular expression contatining two subexpressions ("...(...)...(...)..."), the name and the value of the entry
     */
    blocxx::String regExpr;
    /**    
     * Writing description;
     * A pair item is a printf format string containing two %s placeholders for the name and the value.
     */
    blocxx::String out; 
};

/**
 * @brief Section description of the INI parser
 *
 * An section is described by a beginning and an ending description ( optional ).
 * If there is no ending description the current sections ends if the next beginning
 * description has been found.
 */
struct SectionDescr
{
    /**    
     * Decribes the begin descripiton of a section.
     */
    
    IoPatternDescr begin; // Begin of a section
    
    /**    
     * Decribes the end descripiton of a section (optional).
     */

    IoPatternDescr end; 
    /**    
     * Flag, if a seleciton has an end description.
     */
    
    bool end_valid; // 
};


/**
 * @brief Entry description of the INI parser
 *
 * Describes an entry of an ini file. The normal case will be single line values like
 * <key> = <value>.
 *
 * If there may be values spread over more than one line this should define its parsing.
 * Please note that main purpose for this are lines broken by accident, for example if
 * some editor breaks longer lines. Example:
 * @code
 *     Key="value value
 *     still value
 *     still value"
 *     
 * @endcode
 * Then begin regexp is: ([^=]+)="([^"]*) and end regexp is ([^"]"). These are compared at
 * the end so they are the last possibility. But once we get into this "divided line" by
 * accident, it becomes greedy, so be carefull to forgotten ". If "multiline" is not present,
 * this mechanism does not take in effect of course.
 */

struct EntryDescr
{
    /**
    * Description of a single-line values, the normal case.
    */

    IoPatternDescr line;
    /**
    * String which marks the beginning of a value.
    */
    blocxx::String multiBegin;
    /**
    * String which marks the ending of a value.
    */
    blocxx::String multiEnd;
    /**
    * Flag if the multiline has been specified
    */

    bool multiline_valid;
};


}	// namespace INI
}	// namespace LIMAL_NAMESPACE


#endif  // LIMAL_INI_PARSERDESCR_HPP
/* vim: set ts=8 sts=8 sw=8 ai noet: */
