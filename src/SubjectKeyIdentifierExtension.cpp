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

  File:       SubjectKeyIdentifierExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension()
    : ExtensionBase()
{
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(CA& ca, Type type)
    : ExtensionBase()
{
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(bool autoDetect)
    : ExtensionBase()
{
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(const String& keyid)
    : ExtensionBase()
{
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(const SubjectKeyIdentifierExtension& extension)
    : ExtensionBase()
{
}

SubjectKeyIdentifierExtension::~SubjectKeyIdentifierExtension()
{
}


SubjectKeyIdentifierExtension&
SubjectKeyIdentifierExtension::operator=(const SubjectKeyIdentifierExtension& extension)
{
    return *this;
}

void
SubjectKeyIdentifierExtension::enableAutoDetection()
{
    autodetect = true;
}


void
SubjectKeyIdentifierExtension::setKeyID(const String& keyid)
{
    autodetect = false;
    this->keyid = keyid;
}


blocxx::String
SubjectKeyIdentifierExtension::getKeyID() const
{
    return keyid;
}


void
SubjectKeyIdentifierExtension::commit2Config(CA& ca, Type type)
{
}


