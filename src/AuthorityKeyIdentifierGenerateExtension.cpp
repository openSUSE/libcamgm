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

  File:       AuthorityKeyIdentifierGenerateExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension()
    : ExtensionBase()
{}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(CA& ca, Type type)
    : ExtensionBase()
{}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(KeyID kid, Issuer iss)
    : ExtensionBase()
{}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(const AuthorityKeyIdentifierGenerateExtension& extension)
    : ExtensionBase()
{}

AuthorityKeyIdentifierGenerateExtension::~AuthorityKeyIdentifierGenerateExtension()
{}


AuthorityKeyIdentifierGenerateExtension& 
AuthorityKeyIdentifierGenerateExtension::operator=(const AuthorityKeyIdentifierGenerateExtension& extension)
{
    return *this;
}

void
AuthorityKeyIdentifierGenerateExtension::setKeyID(KeyID kid)
{
    keyid = kid;
}

AuthorityKeyIdentifierGenerateExtension::KeyID
AuthorityKeyIdentifierGenerateExtension::getKeyID() const
{
    return keyid;
}

void
AuthorityKeyIdentifierGenerateExtension::setIssuer(Issuer iss)
{
    issuer = iss;
}

AuthorityKeyIdentifierGenerateExtension::Issuer
AuthorityKeyIdentifierGenerateExtension::getIssuer() const
{
    return issuer;
}

void
AuthorityKeyIdentifierGenerateExtension::commit2Config(CA& ca, Type type)
{

}

