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

#include  <limal/ca-mgm/X509v3CRLExtensions.hpp>
#include  <limal/Exception.hpp>

#include  "X509v3CRLExtensionsImpl.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

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

blocxx::StringArray
X509v3CRLExts::verify() const
{
	StringArray result;

	result.appendArray(m_impl->authorityKeyIdentifier.verify());
	result.appendArray(m_impl->issuerAlternativeName.verify());

	LOGIT_DEBUG_STRINGARRAY("X509v3CRLExts::verify()", result);
	return result;;
}

blocxx::StringArray
X509v3CRLExts::dump() const
{
	StringArray result;
	result.append("X509v3CRLExts::dump()");

	result.appendArray(m_impl->authorityKeyIdentifier.dump());
	result.appendArray(m_impl->issuerAlternativeName.dump());

	return result;
}

//    protected:
X509v3CRLExts::X509v3CRLExts()
	: m_impl(new X509v3CRLExtsImpl())
{}

}
