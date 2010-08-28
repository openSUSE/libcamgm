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

  File:       ValuePerlRECheck.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValuePerlRECheck.cpp
 * @brief  Implements an perl regex based check.
 */
#include  <ca-mgm/config.h>
#include  <ca-mgm/ValuePerlRECheck.hpp>

#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/String.hpp>


namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
ValuePerlRECheck::ValuePerlRECheck(const std::string &regex,
                                   bool                  icase,
                                   bool                  utf8)
	: ValueCheckBase()
	, m_reg(regex, (utf8 ? PCRE_UTF8 : 0) |
	               (icase ? PCRE_CASELESS : 0))
{
}


// -------------------------------------------------------------------
/*
ValuePerlRECheck::ValuePerlRECheck(const ValuePerlRECheck & check)
	: ValueCheckBase()
	, m_reg(m_reg)
{
}
*/


// -------------------------------------------------------------------
bool
ValuePerlRECheck::isValid(const std::string &value) const
{
	return m_reg.match(value);
}


// -------------------------------------------------------------------
std::string
ValuePerlRECheck::explain(const std::string &value) const
{
	return str::form("ValuePerlRECheck('%s' =~ /%s/%s)",
	                      value.c_str(), m_reg.patternString().c_str(),
			      (m_reg.compileFlags() & PCRE_CASELESS ? "i" : ""));
}


}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
