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

  File:       ValuePosixRECheck.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValuePosixRECheck.cpp
 * @brief  Implements an posix regex based check.
 */
#include  <limal/ca-mgm/config.h>
#include  <limal/ValuePosixRECheck.hpp>

#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/Format.hpp>


#ifdef BLOCXX_HAVE_REGEX
namespace LIMAL_NAMESPACE
{

using namespace blocxx;


// -------------------------------------------------------------------
ValuePosixRECheck::ValuePosixRECheck(const blocxx::String &regex,
                                     bool                  icase)
	: ValueCheckBase()
	, m_reg(regex, REG_EXTENDED | REG_NOSUB | (icase ? REG_ICASE : 0))
{
}


// -------------------------------------------------------------------
/*
ValuePosixRECheck::ValuePosixRECheck(const ValuePosixRECheck & check)
	: ValueCheckBase()
	, m_reg(m_reg)
{
}
*/


// -------------------------------------------------------------------
bool
ValuePosixRECheck::isValid(const blocxx::String &value) const
{
	return m_reg.match(value);
}


// -------------------------------------------------------------------
blocxx::String
ValuePosixRECheck::explain(const blocxx::String &value) const
{
	return blocxx::Format("ValuePosixRECheck('%1' =~ /%2/%3)",
	                      value, m_reg.patternString(),
			      (m_reg.compileFlags() & REG_ICASE ? "i" : ""));
}


}       // End of LIMAL_NAMESPACE
#endif
// vim: set ts=8 sts=8 sw=8 ai noet:
