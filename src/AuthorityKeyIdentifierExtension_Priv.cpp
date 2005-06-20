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

  File:       AuthorityKeyIdentifierExtension_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "AuthorityKeyIdentifierExtension_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv()
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv(X509* cert)
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv(X509_CRL* crl)
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Priv::~AuthorityKeyIdentifierExtension_Priv()
{
}
        
void
AuthorityKeyIdentifierExtension_Priv::setKeyID(const String& kid)
{
    keyid = kid;
}

void
AuthorityKeyIdentifierExtension_Priv::setDirName(const String& dirName)
{
    this->DirName = dirName;
}

void
AuthorityKeyIdentifierExtension_Priv::setSerial(const String& serial)
{
    this->serial = serial;
}

//  private:
AuthorityKeyIdentifierExtension_Priv::AuthorityKeyIdentifierExtension_Priv(const AuthorityKeyIdentifierExtension_Priv& extension)
    : AuthorityKeyIdentifierExtension(extension)
{
}
        
AuthorityKeyIdentifierExtension_Priv&
AuthorityKeyIdentifierExtension_Priv::operator=(const AuthorityKeyIdentifierExtension_Priv& extension)
{
    return *this;
}
