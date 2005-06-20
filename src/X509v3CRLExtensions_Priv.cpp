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

  File:       X509v3CRLExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "X509v3CRLExtensions_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv()
    : X509v3CRLExtensions()
{
}

X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv(X509_CRL* crl)
    : X509v3CRLExtensions()
{
}

X509v3CRLExtensions_Priv::~X509v3CRLExtensions_Priv()
{
}

void
X509v3CRLExtensions_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext)
{
    authorityKeyIdentifier = ext;
}

void
X509v3CRLExtensions_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    issuerAlternativeName = ext;
}


//  private:
X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv(const X509v3CRLExtensions_Priv& extensions)
    : X509v3CRLExtensions(extensions)
{
}

X509v3CRLExtensions_Priv&
X509v3CRLExtensions_Priv::operator=(const X509v3CRLExtensions_Priv& extensions)
{
    return *this;
}
