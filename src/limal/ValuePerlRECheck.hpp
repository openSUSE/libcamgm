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

  File:       ValuePerlRECheck.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValuePerlRECheck.hpp
 * @brief  Implements an perl regex based value check.
 */
#ifndef    LIMAL_VALUE_PERL_REGEX_CHECK_HPP
#define    LIMAL_VALUE_PERL_REGEX_CHECK_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ValueCheck.hpp>

#include  <blocxx/Types.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/PerlRegEx.hpp>

namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
#ifdef BLOCXX_HAVE_PCRE
/**
 * @brief Perl regex value check.
 *
 * The ValuePerlRECheck implements a simple perl regex
 * match check that can be used in ValueCheck.
 */
class ValuePerlRECheck: public ValueCheckBase
{
public:
	/**
	 * Constructor compiling a perl regular expression used
	 * to validate a value.
	 *
	 * The match is case sensitive unless the icase flag is set.
	 *
	 * @param regex  Perl regular expression string.
	 * @param icase  Match case insensitive.
	 * @param utf8   Whether to enable UTF8 mode.
	 * @throws blocxx::RegExCompileException on invalid pattern
	 * or enabled utf8 mode with pcre that does not support it.
	 */
	ValuePerlRECheck(const blocxx::String &regex,
	                 bool icase  = false,
	                 bool utf8   = false);

	/**
	 * Return whether the regular expression matches the
	 * specified string value.
	 *
	 * @param value A string value.
	 * @return true, if the regex matches the value, false on no match.
	 * @throws blocxx::RegExExecuteException on execute failure.
	 */
	virtual bool
	isValid(const blocxx::String &value) const;

	/**
	 * Return a string showing the regex matching the
	 * specified string value.
	 *
	 * @param value A string value.
	 * @return A string showing the check.
	 */
	virtual blocxx::String
	explain(const blocxx::String &value) const;

private:
	blocxx::PerlRegEx  m_reg;
};
#else
#warning PerlRegEx is not avaliable in blocxx
#endif


}       // End of LIMAL_NAMESPACE
#endif  // LIMAL_VALUE_PERL_REGEX_CHECK_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
