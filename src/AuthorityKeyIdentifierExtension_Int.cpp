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

  File:       AuthorityKeyIdentifierExtension_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "AuthorityKeyIdentifierExtension_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierExtension_Int::AuthorityKeyIdentifierExtension_Int()
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Int::AuthorityKeyIdentifierExtension_Int(X509* cert)
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Int::AuthorityKeyIdentifierExtension_Int(X509_CRL* crl)
    : AuthorityKeyIdentifierExtension()
{
}

AuthorityKeyIdentifierExtension_Int::~AuthorityKeyIdentifierExtension_Int()
{
}
        
void
AuthorityKeyIdentifierExtension_Int::setKeyID(const String& kid)
{
    keyid = kid;
}

void
AuthorityKeyIdentifierExtension_Int::setDirName(const String& dirName)
{
    this->DirName = dirName;
}

void
AuthorityKeyIdentifierExtension_Int::setSerial(const String& serial)
{
    this->serial = serial;
}

//  private:
AuthorityKeyIdentifierExtension_Int::AuthorityKeyIdentifierExtension_Int(const AuthorityKeyIdentifierExtension_Int& extension)
    : AuthorityKeyIdentifierExtension(extension)
{
}
        
AuthorityKeyIdentifierExtension_Int&
AuthorityKeyIdentifierExtension_Int::operator=(const AuthorityKeyIdentifierExtension_Int& extension)
{
    return *this;
}
