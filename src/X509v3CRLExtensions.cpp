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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CRLExtensions::X509v3CRLExtensions(const X509v3CRLExtensions& extensions)
{
}

X509v3CRLExtensions::~X509v3CRLExtensions()
{
}

X509v3CRLExtensions&
X509v3CRLExtensions::operator=(const X509v3CRLExtensions& extensions)
{
    return *this;
}

AuthorityKeyIdentifierExtension
X509v3CRLExtensions::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

IssuerAlternativeNameExtension
X509v3CRLExtensions::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

//    protected:
X509v3CRLExtensions::X509v3CRLExtensions()
{
}

