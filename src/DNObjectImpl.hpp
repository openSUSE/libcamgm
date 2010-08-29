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
#ifndef    CA_MGM_DN_OBJECT_IMPL_HPP
#define    CA_MGM_DN_OBJECT_IMPL_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <list>



namespace CA_MGM_NAMESPACE {

class RDNObjectImpl
{
public:
	RDNObjectImpl()
		: type(std::string())
		, value(std::string())
		, prompt(std::string())
		, min(0)
		, max(0)
	{}

	RDNObjectImpl(const RDNObjectImpl& impl)
		: type(impl.type)
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

	std::string type;
	std::string value;

	std::string prompt;
	uint32_t min;
	uint32_t max;
};

class DNObjectImpl
{
public:
	DNObjectImpl()
		: dn(std::list<RDNObject>())
	{}

	DNObjectImpl(const DNObjectImpl& impl)
		: dn(impl.dn)
	{}

	~DNObjectImpl() {}

	DNObjectImpl* clone() const
	{
		return new DNObjectImpl(*this);
	}

	std::list<RDNObject> dn;

};

}

#endif // CA_MGM_DN_OBJECT_IMPL_HPP
