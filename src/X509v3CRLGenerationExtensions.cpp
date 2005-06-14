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
{
}

X509v3CRLGenerationExtensions::~X509v3CRLGenerationExtensions()
{
}

X509v3CRLGenerationExtensions&
X509v3CRLGenerationExtensions::operator=(const X509v3CRLGenerationExtensions& extension)
{
    return *this;
}

void
X509v3CRLGenerationExtensions::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExtension &ext)
{
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

