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
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CRLGenerationExtensions::X509v3CRLGenerationExtensions()
{
}

X509v3CRLGenerationExtensions::X509v3CRLGenerationExtensions(CA& ca, Type type)
{
}

X509v3CRLGenerationExtensions::X509v3CRLGenerationExtensions(const X509v3CRLGenerationExtensions& extensions)
    : authorityKeyIdentifier(extensions.authorityKeyIdentifier),
      issuerAlternativeName(extensions.issuerAlternativeName)
{
}

X509v3CRLGenerationExtensions::~X509v3CRLGenerationExtensions()
{}

X509v3CRLGenerationExtensions&
X509v3CRLGenerationExtensions::operator=(const X509v3CRLGenerationExtensions& extension)
{
    if(this == &extension) return *this;
    
    authorityKeyIdentifier = extension.authorityKeyIdentifier;
    issuerAlternativeName  = extension.issuerAlternativeName;
    
    return *this;
}

void
X509v3CRLGenerationExtensions::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CRLGenerationExtensions::setAuthorityKeyIdentifier invalid value");
    }
    authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExtension
X509v3CRLGenerationExtensions::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

void
X509v3CRLGenerationExtensions::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CRLGenerationExtensions::setIssuerAlternativeName invalid value");
    }
    issuerAlternativeName = ext;
}

IssuerAlternativeNameExtension
X509v3CRLGenerationExtensions::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

void
X509v3CRLGenerationExtensions::commit2Config(CA& ca, Type type)
{
}

bool
X509v3CRLGenerationExtensions::valid() const
{
    if(!authorityKeyIdentifier.valid()) return false;
    if(!issuerAlternativeName.valid())  return false;
    return true;
}

blocxx::StringArray
X509v3CRLGenerationExtensions::verify() const
{
    StringArray result;

    result.appendArray(authorityKeyIdentifier.verify());
    result.appendArray(issuerAlternativeName.verify());
    
    LOGIT_DEBUG_STRINGARRAY("X509v3CRLGenerationExtensions::verify()", result);
    return result;;
}

