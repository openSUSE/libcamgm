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
#include  <limal/ca-mgm/config.h>
#include  <limal/ValuePerlRECheck.hpp>

#include  <blocxx/Types.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/Format.hpp>


#ifdef BLOCXX_HAVE_PCRE
namespace LIMAL_NAMESPACE
{

using namespace blocxx;


// -------------------------------------------------------------------
ValuePerlRECheck::ValuePerlRECheck(const blocxx::String &regex,
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
ValuePerlRECheck::isValid(const blocxx::String &value) const
{
	return m_reg.match(value);
}


// -------------------------------------------------------------------
blocxx::String
ValuePerlRECheck::explain(const blocxx::String &value) const
{
	return blocxx::Format("ValuePerlRECheck('%1' =~ /%2/%3)",
	                      value, m_reg.patternString(),
			      (m_reg.compileFlags() & PCRE_CASELESS ? "i" : ""));
}


}       // End of LIMAL_NAMESPACE
#endif
// vim: set ts=8 sts=8 sw=8 ai noet:
