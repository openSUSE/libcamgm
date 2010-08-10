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
#include  <limal/String.hpp>


namespace LIMAL_NAMESPACE
{

// -------------------------------------------------------------------
ValuePosixRECheck::ValuePosixRECheck(const std::string &regex,
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
ValuePosixRECheck::isValid(const std::string &value) const
{
	return m_reg.match(value);
}


// -------------------------------------------------------------------
std::string
ValuePosixRECheck::explain(const std::string &value) const
{
    return str::form("ValuePosixRECheck('%s' =~ /%s/%s)",
                     value.c_str(), m_reg.patternString().c_str(),
                     (m_reg.compileFlags() & REG_ICASE ? "i" : ""));
}


}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
