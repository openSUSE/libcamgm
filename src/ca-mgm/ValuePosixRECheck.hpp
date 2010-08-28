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

#include <ca-mgm/config.h>
#include <ca-mgm/ValueCheck.hpp>

#include <ca-mgm/CommonData.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/PosixRegEx.hpp>

namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
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
	 * @throws ca_mgm::ValueException on invalid pattern
	 */
	ValuePosixRECheck(const std::string &regex,
	                  bool icase = false);

	/**
	 * Return whether the regular expression matches the
	 * specified string value.
	 *
	 * @param value A string value.
	 * @return true, if the regex matches the value, false on no match.
	 * @throws ca_mgm::ValueException on execute failure.
	 */
	virtual bool
	isValid(const std::string &value) const;

	/**
	 * Return a string showing the regex matching the
	 * specified string value.
	 *
	 * @param value A string value.
	 * @return A string showing the check.
	 */
	virtual std::string
	explain(const std::string &value) const;

private:
	PosixRegEx  m_reg;
};

}      // End of LIMAL_NAMESPACE
#endif // LIMAL_VALUE_POSIX_REGEX_CHECK_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
