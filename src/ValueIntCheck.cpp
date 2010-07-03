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

#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/String.hpp>

namespace LIMAL_NAMESPACE
{

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
ValueIntCheck::ValueIntCheck(uint64_t minValue,
                             uint64_t maxValue,
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
ValueIntCheck::ValueIntCheck(int64_t minValue,
                             int64_t maxValue,
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
ValueIntCheck::isValid(const std::string &value) const
{
	if( m_sign) {
		int64_t val  = str::strtonum<int64_t>(value);
		if( m_incl)
		{
			return (val >= m_min.s && val <= m_max.s);
		}
		else
		{
			return (val > m_min.s && val < m_max.s);
		}
	} else {
		uint64_t val = str::strtonum<uint64_t>(value);
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
std::string
ValueIntCheck::explain(const std::string &value) const
{
	std::string s;
	std::string o(m_incl ? "=" : "");
	if( m_sign) {
		s = str::form("ValueIntCheck(%s >%s %lld && %s <%s %lld)",
		              value.c_str(), o.c_str(), m_min.s,
                      value.c_str(), o.c_str(), m_max.s);
	}
	else
	{
		s = str::form("ValueIntCheck('%s' >%s %lld && '%s' <%s %lld)",
		              value.c_str(), o.c_str(), m_min.u,
                      value.c_str(), o.c_str(), m_max.u);
	}
	return s;
}


}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
