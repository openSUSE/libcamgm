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


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class AuthorityKeyIdentifierExtImpl
{
public:

	AuthorityKeyIdentifierExtImpl()
		: keyid(std::string())
		, DirName(std::string())
		, serial(std::string())
	{}

	AuthorityKeyIdentifierExtImpl(const AuthorityKeyIdentifierExtImpl &impl)
		: keyid(impl.keyid)
		, DirName(impl.DirName)
		, serial(impl.serial)
	{}

	virtual ~AuthorityKeyIdentifierExtImpl() {}

	AuthorityKeyIdentifierExtImpl* clone() const
	{
		return new AuthorityKeyIdentifierExtImpl(*this);
	}

	std::string keyid;
	std::string DirName;
	std::string serial;
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

std::string
AuthorityKeyIdentifierExt::getKeyID() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->keyid;
}

std::string
AuthorityKeyIdentifierExt::getDirName() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->DirName;
}

std::string
AuthorityKeyIdentifierExt::getSerial() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("AuthorityKeyIdentifierExt is not present."));
	}
	return m_impl->serial;
}

bool
AuthorityKeyIdentifierExt::valid() const
{
	return true;
}

std::vector<std::string>
AuthorityKeyIdentifierExt::verify() const
{
	return std::vector<std::string>();
}

std::vector<std::string>
AuthorityKeyIdentifierExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("AuthorityKeyIdentifierExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("KeyID = " + getKeyID());
	result.push_back("DirName = " + getDirName());
	result.push_back("serial = " + getSerial());

	return result;
}

// protected

void
AuthorityKeyIdentifierExt::setKeyID(const std::string& kid)
{
	m_impl->keyid = kid;
}

void
AuthorityKeyIdentifierExt::setDirName(const std::string& dirName)
{
	m_impl->DirName = dirName;
}

void
AuthorityKeyIdentifierExt::setSerial(const std::string& serial)
{
	m_impl->serial = serial;
}

// private
void
AuthorityKeyIdentifierExt::commit2Config(CA&, Type) const
{}

}
