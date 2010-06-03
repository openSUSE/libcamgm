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

  File:       ValueIntCheck.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

  Purpose:

/-*/
/**
 * @file   ValueIntCheck.cpp
 * @brief  Implements an integer range check
 */
#include  <limal/ca-mgm/config.h>
#include  <limal/ValueIntCheck.hpp>

#include  <blocxx/Types.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/Format.hpp>

namespace LIMAL_NAMESPACE
{

using namespace blocxx;


// -------------------------------------------------------------------
ValueIntCheck::ValueIntCheck(int            minValue,
                             int            maxValue,
                             bool inclusiveRange)
	: ValueCheckBase()
	, m_sign(true)
	, m_incl(inclusiveRange)
{
	m_min.s = minValue;
	m_max.s = maxValue;
}


// -------------------------------------------------------------------
ValueIntCheck::ValueIntCheck(blocxx::UInt64 minValue,
                             blocxx::UInt64 maxValue,
                             bool inclusiveRange)
	: ValueCheckBase()
	, m_sign(false)
	, m_incl(inclusiveRange)
{
	m_min.u = minValue;
	m_max.u = maxValue;
}


// -------------------------------------------------------------------
ValueIntCheck::
ValueIntCheck::ValueIntCheck(blocxx::Int64 minValue,
                             blocxx::Int64 maxValue,
                             bool inclusiveRange)
	: ValueCheckBase()
	, m_sign(true)
	, m_incl(inclusiveRange)
{
	m_min.s = minValue;
	m_max.s = maxValue;
}


// -------------------------------------------------------------------
bool
ValueIntCheck::isValid(const blocxx::String &value) const
{
	if( m_sign) {
		Int64 val  = value.toInt64();
		if( m_incl)
		{
			return (val >= m_min.s && val <= m_max.s);
		}
		else
		{
			return (val > m_min.s && val < m_max.s);
		}
	} else {
		UInt64 val = value.toUInt64();
		if( m_incl)
		{
			return (val >= m_min.u && val <= m_max.u);
		}
		else
		{
			return (val > m_min.u && val < m_max.u);
		}
	}
}


// -------------------------------------------------------------------
blocxx::String
ValueIntCheck::explain(const blocxx::String &value) const
{
	String s;
	String o(m_incl ? "=" : "");
	if( m_sign) {
		s = Format("ValueIntCheck('%1' >%2 %3 && '%4' <%5 %6)",
		           value, o, m_min.s, value, o, m_max.s);
	}
	else
	{
		s = Format("ValueIntCheck('%1' >%2 %3 && '%4' <%5 %6)",
		           value, o, m_min.u, value, o, m_max.u);
	}
	return s;
}


}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
