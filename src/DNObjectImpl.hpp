/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                           |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       DNObjectImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_IMPL_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_IMPL_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/List.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>


namespace CA_MGM_NAMESPACE {

class RDNObjectImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	RDNObjectImpl()
		: type(String())
		, value(String())
		, prompt(String())
		, min(0)
		, max(0)
	{}

	RDNObjectImpl(const RDNObjectImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, type(impl.type)
		, value(impl.value)
		, prompt(impl.prompt)
		, min(impl.min)
		, max(impl.max)
	{}

	~RDNObjectImpl() {}

	RDNObjectImpl* clone() const
	{
		return new RDNObjectImpl(*this);
	}

	blocxx::String type;
	blocxx::String value;

	blocxx::String prompt;
	blocxx::UInt32 min;
	blocxx::UInt32 max;
};

class DNObjectImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	DNObjectImpl()
		: dn(std::list<RDNObject>())
	{}

	DNObjectImpl(const DNObjectImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, dn(impl.dn)
	{}

	~DNObjectImpl() {}

	DNObjectImpl* clone() const
	{
		return new DNObjectImpl(*this);
	}

	std::list<RDNObject> dn;

};

}

#endif // LIMAL_CA_MGM_DN_OBJECT_IMPL_HPP
