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

  File:       X509v3CRLExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <ca-mgm/X509v3CRLExtensions.hpp>
#include  <ca-mgm/Exception.hpp>

#include  "X509v3CRLExtensionsImpl.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

X509v3CRLExts::X509v3CRLExts(const X509v3CRLExts& extensions)
	: m_impl(extensions.m_impl)
{}

X509v3CRLExts::~X509v3CRLExts()
{}

X509v3CRLExts&
X509v3CRLExts::operator=(const X509v3CRLExts& extensions)
{
	if(this == &extensions) return *this;

	m_impl = extensions.m_impl;

	return *this;
}

AuthorityKeyIdentifierExt
X509v3CRLExts::getAuthorityKeyIdentifier() const
{
	return m_impl->authorityKeyIdentifier;
}

IssuerAlternativeNameExt
X509v3CRLExts::getIssuerAlternativeName() const
{
	return m_impl->issuerAlternativeName;
}

bool
X509v3CRLExts::valid() const
{
	if(!m_impl->authorityKeyIdentifier.valid()) return false;
	if(!m_impl->issuerAlternativeName.valid())  return false;
	return true;
}

std::vector<std::string>
X509v3CRLExts::verify() const
{
	std::vector<std::string> result;

	appendArray(result, m_impl->authorityKeyIdentifier.verify());
	appendArray(result, m_impl->issuerAlternativeName.verify());

	LOGIT_DEBUG_STRINGARRAY("X509v3CRLExts::verify()", result);
	return result;;
}

std::vector<std::string>
X509v3CRLExts::dump() const
{
	std::vector<std::string> result;
	result.push_back("X509v3CRLExts::dump()");

	appendArray(result, m_impl->authorityKeyIdentifier.dump());
	appendArray(result, m_impl->issuerAlternativeName.dump());

	return result;
}

//    protected:
X509v3CRLExts::X509v3CRLExts()
	: m_impl(new X509v3CRLExtsImpl())
{}

}
