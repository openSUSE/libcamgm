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

  File:       ValuePosixRECheck.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValuePosixRECheck.hpp
 * @brief  Implements a posix regex based value check.
 */
#ifndef   LIMAL_VALUE_POSIX_REGEX_CHECK_HPP
#define   LIMAL_VALUE_POSIX_REGEX_CHECK_HPP

#include <limal/ca-mgm/config.h>
#include <limal/ValueCheck.hpp>

#include  <limal/ca-mgm/CommonData.hpp>
#include <blocxx/String.hpp>
#include <blocxx/PosixRegEx.hpp>

namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
#ifdef BLOCXX_HAVE_REGEX
/**
 * @brief Posix regex value check.
 *
 * The ValuePosixRECheck implements a simple posix regex
 * match check that can be used in ValueCheck.
 */
class ValuePosixRECheck: public ValueCheckBase
{
public:
	/**
	 * Constructor compiling a extended regular expression
	 * used to validate a value.
	 *
	 * The match is case sensitive unless the icase flag is set.
	 *
	 * @param regex	 Extended regular expression string.
	 * @param icase  Match case insensitive.
	 * @throws blocxx::RegExCompileException on invalid pattern
	 */
	ValuePosixRECheck(const blocxx::String &regex,
	                  bool icase = false);

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
	blocxx::PosixRegEx  m_reg;
};
#else
#warning PosixRegEx is not avaliable in blocxx
#endif


}      // End of LIMAL_NAMESPACE
#endif // LIMAL_VALUE_POSIX_REGEX_CHECK_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
