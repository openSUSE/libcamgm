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

  File:       AuthorityKeyIdentifierExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class AuthorityKeyIdentifierExtImpl : public blocxx::COWIntrusiveCountableBase
{
public:

	AuthorityKeyIdentifierExtImpl()
		: keyid(String())
		, DirName(String())
		, serial(String())
	{}

	AuthorityKeyIdentifierExtImpl(const AuthorityKeyIdentifierExtImpl &impl)
		: COWIntrusiveCountableBase(impl)
		, keyid(impl.keyid)
		, DirName(impl.DirName)
		, serial(impl.serial)
	{}

	virtual ~AuthorityKeyIdentifierExtImpl() {}

	AuthorityKeyIdentifierExtImpl* clone() const
	{
		return new AuthorityKeyIdentifierExtImpl(*this);
	}

	String keyid;
	String DirName;
	String serial;
};

// ======================================================================

AuthorityKeyIdentifierExt::AuthorityKeyIdentifierExt()
	: ExtensionBase()
	, m_impl(new AuthorityKeyIdentifierExtImpl())
{}

AuthorityKeyIdentifierExt::AuthorityKeyIdentifierExt(const AuthorityKeyIdentifierExt& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

AuthorityKeyIdentifierExt::~AuthorityKeyIdentifierExt()
{}

AuthorityKeyIdentifierExt&
AuthorityKeyIdentifierExt::operator=(const AuthorityKeyIdentifierExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}

blocxx::String
AuthorityKeyIdentifierExt::getKeyID() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->keyid;
}

blocxx::String
AuthorityKeyIdentifierExt::getDirName() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->DirName;
}

blocxx::String
AuthorityKeyIdentifierExt::getSerial() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->serial;
}

bool
AuthorityKeyIdentifierExt::valid() const
{
	return true;
}

blocxx::StringArray
AuthorityKeyIdentifierExt::verify() const
{
	return blocxx::StringArray();
}

blocxx::StringArray
AuthorityKeyIdentifierExt::dump() const
{
	StringArray result;
	result.append("AuthorityKeyIdentifierExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	result.append("KeyID = " + getKeyID());
	result.append("DirName = " + getDirName());
	result.append("serial = " + getSerial());

	return result;
}

// protected

void
AuthorityKeyIdentifierExt::setKeyID(const String& kid)
{
	m_impl->keyid = kid;
}

void
AuthorityKeyIdentifierExt::setDirName(const String& dirName)
{
	m_impl->DirName = dirName;
}

void
AuthorityKeyIdentifierExt::setSerial(const String& serial)
{
	m_impl->serial = serial;
}

// private
void
AuthorityKeyIdentifierExt::commit2Config(CA&, Type) const
{}

}
}
