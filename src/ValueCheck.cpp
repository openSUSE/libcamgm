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

  File:       ValueCheck.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   ValueCheck.cpp
 * @brief  Provides class allowing to implement chained
 *         checks on string values.
 */
#include  <limal/ca-mgm/config.h>
#include  <limal/ValueCheck.hpp>

#include  <limal/Exception.hpp>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/String.hpp>
#include  <blocxx/RefCount.hpp>
#include  <list>

#include  "Utils.hpp"


namespace LIMAL_NAMESPACE
{

using namespace blocxx;


// -------------------------------------------------------------------
ValueCheck::ValueCheck()
	: ValueCheckBase()
	, m_cop(E_AND)
	, m_neg(false)
	, m_self(NULL)
{
}


// -------------------------------------------------------------------
ValueCheck::ValueCheck(ValueCheckBase *check)
	: ValueCheckBase()
	, m_cop(E_AND)
	, m_neg(false)
	, m_self(check)
{
	incRCnt(m_self);
}


// -------------------------------------------------------------------
ValueCheck::ValueCheck(const ValueCheck &ref)
	: ValueCheckBase()
	, m_cop(ref.m_cop)
	, m_neg(ref.m_neg)
	, m_self(ref.m_self)
	, m_list(ref.m_list)
{
	incRCnt(m_self);
}


// -------------------------------------------------------------------
ValueCheck::ValueCheck(const ValueCheck &ref, ECheckOp op)
	: ValueCheckBase()
	, m_cop(op)
	, m_neg(ref.m_neg)
	, m_self(ref.m_self)
	, m_list(ref.m_list)
{
	incRCnt( m_self);
}


// -------------------------------------------------------------------
ValueCheck::~ValueCheck()
{
	delRCnt(m_self);
	m_self = NULL;
}


// -------------------------------------------------------------------
ValueCheck &
ValueCheck::operator=(const ValueCheck &ref)
{
	incRCnt(ref.m_self);
	delRCnt(m_self);
	m_cop  = ref.m_cop;
	m_neg  = ref.m_neg;
	m_self = ref.m_self;
	m_list = ref.m_list;
	return *this;
}


// -------------------------------------------------------------------
ValueCheck &
ValueCheck::operator=(ValueCheckBase *check)
{
	incRCnt(check);
	delRCnt(m_self);
	m_self = check;
	return *this;
}


// -------------------------------------------------------------------
bool
ValueCheck::isValid(const std::string &value) const
{
	if( !m_self)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		__("The value check may not contain a NULL pointer."));
	}

	bool ret = m_self->isValid(value);

	if( !m_list.empty())
	{
		std::list<ValueCheck>::const_iterator i;
		for( i = m_list.begin(); i != m_list.end(); ++i)
		{
			if( i->m_cop == E_AND)
			{
				ret = ret && i->isValid(value);
			}
			else
			{
				ret = ret || i->isValid(value);
			}
		}
	}
	return m_neg ? !ret : ret;
}


// -------------------------------------------------------------------
std::string
ValueCheck::explain(const std::string &value) const
{
	if( !m_self)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		__("The value check may not contain a NULL pointer."));
	}

	std::string res(m_self->explain(value));
	if( !m_list.empty())
	{
		std::list<ValueCheck>::const_iterator i;
		for( i = m_list.begin(); i != m_list.end(); ++i)
		{
			if( i->m_cop == E_AND)
			{
				res += " && " + i->explain(value);
			}
			else
			{
				res += " || " + i->explain(value);
			}
		}
	}
	res = (m_neg ? "!(" : "(") + res + ")";

	return res;
}


// -------------------------------------------------------------------
ValueCheck&
ValueCheck::Not()
{
	m_neg = !m_neg;
	return *this;
}


// -------------------------------------------------------------------
ValueCheck&
ValueCheck::And(const ValueCheck &ref)
{
	m_list.push_back(ValueCheck(ref, E_AND));
	return *this;
}


// -------------------------------------------------------------------
ValueCheck&
ValueCheck::And(ValueCheckBase *check)
{
	m_list.push_back(ValueCheck(check, E_AND));
	return *this;
}


// -------------------------------------------------------------------
ValueCheck&
ValueCheck::Or(const ValueCheck &ref)
{
	m_list.push_back(ValueCheck(ref, E_OR));
	return *this;
}


// -------------------------------------------------------------------
ValueCheck&
ValueCheck::Or(ValueCheckBase *check)
{
	m_list.push_back(ValueCheck(check, E_OR));
	return *this;
}


// -------------------------------------------------------------------
inline void
ValueCheck::incRCnt(ValueCheckBase *ptr)
{
	if( ptr)
	{
		ptr->m_rcnt.inc();
	}
	else
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		__("The value check may not contain a NULL pointer."));
	}
}

// -------------------------------------------------------------------
inline void
ValueCheck::delRCnt(ValueCheckBase *ptr)
{
	if( ptr)
	{
		if(ptr->m_rcnt.decAndTest())
		{
			delete ptr;
		}
	}
}


}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet: