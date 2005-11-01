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

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

X509v3CRLExts::X509v3CRLExts(const X509v3CRLExts& extensions)
    : authorityKeyIdentifier(extensions.authorityKeyIdentifier),
      issuerAlternativeName(extensions.issuerAlternativeName)
{
}

X509v3CRLExts::~X509v3CRLExts()
{}

X509v3CRLExts&
X509v3CRLExts::operator=(const X509v3CRLExts& extensions)
{
    if(this == &extensions) return *this;
    
    authorityKeyIdentifier = extensions.authorityKeyIdentifier;
    issuerAlternativeName  = extensions.issuerAlternativeName;
    
    return *this;
}

AuthorityKeyIdentifierExt
X509v3CRLExts::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

IssuerAlternativeNameExt
X509v3CRLExts::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

bool
X509v3CRLExts::valid() const
{
    if(!authorityKeyIdentifier.valid()) return false;
    if(!issuerAlternativeName.valid())  return false;
    return true;
}

blocxx::StringArray
X509v3CRLExts::verify() const
{
    StringArray result;

    result.appendArray(authorityKeyIdentifier.verify());
    result.appendArray(issuerAlternativeName.verify());
    
    LOGIT_DEBUG_STRINGARRAY("X509v3CRLExts::verify()", result);
    return result;;
}

blocxx::StringArray
X509v3CRLExts::dump() const
{
    StringArray result;
    result.append("X509v3CRLExts::dump()");

    result.appendArray(authorityKeyIdentifier.dump());
    result.appendArray(issuerAlternativeName.dump());

    return result;
}

//    protected:
X509v3CRLExts::X509v3CRLExts()
{
}

}
}
