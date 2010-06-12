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

  File:       ExtensionBase.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class ExtensionBaseImpl : public COWIntrusiveCountableBase {

public:

	ExtensionBaseImpl(bool extPresent = false, bool extCritical = false)
		: present(extPresent), critical(extCritical)
	{}

	ExtensionBaseImpl(const ExtensionBaseImpl &ebi)
		: COWIntrusiveCountableBase(ebi)
		, present(ebi.present)
		, critical(ebi.critical)
	{}

	virtual ~ExtensionBaseImpl() {}

	ExtensionBaseImpl* clone() const
	{
		return new ExtensionBaseImpl(*this);
	}

	void   setPresent(bool extPresent)   { present  = extPresent;  }
	void   setCritical(bool extCritical) { critical = extCritical; }

	bool   isCritical() const { return (present)?critical:false; }
	bool   isPresent() const  { return present; }

private:
	bool present;
	bool critical;

};

// ================================================================


ExtensionBase::ExtensionBase(bool extPresent, bool extCritical)
	: m_impl(new ExtensionBaseImpl(extPresent, extCritical))
{
}

ExtensionBase::ExtensionBase(const ExtensionBase& extension)
	: m_impl(extension.m_impl)
{}

ExtensionBase::~ExtensionBase()
{}

ExtensionBase&
ExtensionBase::operator=(const ExtensionBase& extension)
{
	if(this == &extension) return *this;

	m_impl   = extension.m_impl;

	return *this;
}

void
ExtensionBase::setPresent(bool extPresent)
{
	LOGIT_DEBUG("ExtensionBase::setPresent(): " << (extPresent ? "true":"false") );
	m_impl->setPresent(extPresent);
}

void
ExtensionBase::setCritical(bool extCritical)
{
	LOGIT_DEBUG("ExtensionBase::setCritical(): " << (extCritical ? "true":"false") );
	setPresent(true);
	m_impl->setCritical(extCritical);
}

bool
ExtensionBase::isCritical() const
{
	return (isPresent())?m_impl->isCritical():false;
}

bool
ExtensionBase::isPresent() const
{
	return m_impl->isPresent();
}

std::vector<blocxx::String>
ExtensionBase::dump() const
{
	std::vector<blocxx::String> result;
	result.push_back("ExtensionBase::dump()");

	result.push_back("is Present = " + Bool(isPresent()).toString());
	if(!isPresent()) return result;

	result.push_back("is Critical = " + Bool(isCritical()).toString());

	return result;
}

}
