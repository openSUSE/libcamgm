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

  File:       X509v3CRLGenerationExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/X509v3CRLGenerationExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

X509v3CRLGenerationExts::X509v3CRLGenerationExts()
{
}

X509v3CRLGenerationExts::X509v3CRLGenerationExts(CAConfig* caConfig, Type type)
    : authorityKeyIdentifier(caConfig, type),
      issuerAlternativeName(caConfig, type)
{
}

X509v3CRLGenerationExts::X509v3CRLGenerationExts(const X509v3CRLGenerationExts& extensions)
    : authorityKeyIdentifier(extensions.authorityKeyIdentifier),
      issuerAlternativeName(extensions.issuerAlternativeName)
{
}

X509v3CRLGenerationExts::~X509v3CRLGenerationExts()
{}

X509v3CRLGenerationExts&
X509v3CRLGenerationExts::operator=(const X509v3CRLGenerationExts& extension)
{
    if(this == &extension) return *this;
    
    authorityKeyIdentifier = extension.authorityKeyIdentifier;
    issuerAlternativeName  = extension.issuerAlternativeName;
    
    return *this;
}

void
X509v3CRLGenerationExts::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CRLGenerationExts::setAuthorityKeyIdentifier invalid value");
    }
    authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExt
X509v3CRLGenerationExts::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

void
X509v3CRLGenerationExts::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CRLGenerationExts::setIssuerAlternativeName invalid value");
    }
    issuerAlternativeName = ext;
}

IssuerAlternativeNameExt
X509v3CRLGenerationExts::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

void
X509v3CRLGenerationExts::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid X509v3RequestExts object");
        BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExts object");
    }
    
    authorityKeyIdentifier.commit2Config(ca, type);
    issuerAlternativeName.commit2Config(ca, type);
}

bool
X509v3CRLGenerationExts::valid() const
{
    if(!authorityKeyIdentifier.valid()) return false;
    if(!issuerAlternativeName.valid())  return false;
    return true;
}

blocxx::StringArray
X509v3CRLGenerationExts::verify() const
{
    StringArray result;

    result.appendArray(authorityKeyIdentifier.verify());
    result.appendArray(issuerAlternativeName.verify());
    
    LOGIT_DEBUG_STRINGARRAY("X509v3CRLGenerationExts::verify()", result);
    return result;;
}

blocxx::StringArray
X509v3CRLGenerationExts::dump() const
{
    StringArray result;
    result.append("X509v3CRLGenerationExts::dump()");

    result.appendArray(authorityKeyIdentifier.dump());
    result.appendArray(issuerAlternativeName.dump());

    return result;
}

}
}
