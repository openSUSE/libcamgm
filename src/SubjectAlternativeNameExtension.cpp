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

  File:       SubjectAlternativeNameExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(CA& ca, Type type)
    : ExtensionBase()
{
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(bool copyEmail,
                                const blocxx::List<LiteralValueBase> &alternativeNameList)
    : ExtensionBase()
{
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& extension)
    : ExtensionBase()
{
}


SubjectAlternativeNameExtension::~SubjectAlternativeNameExtension()
{
}


SubjectAlternativeNameExtension&
SubjectAlternativeNameExtension::operator=(const SubjectAlternativeNameExtension& extension)
{
    return *this;
}


void
SubjectAlternativeNameExtension::setCopyEmail(bool copyEmail)
{
    emailCopy = copyEmail;
}

bool
SubjectAlternativeNameExtension::getCopyEmail() const
{
    return emailCopy;
}

void
SubjectAlternativeNameExtension::setAlternativeNameList(const blocxx::List<LiteralValueBase> &alternativeNameList)
{
    altNameList = alternativeNameList;
}


blocxx::List<LiteralValueBase>
SubjectAlternativeNameExtension::getAlternativeNameList() const
{
    return altNameList;
}

void
SubjectAlternativeNameExtension::addSubjectAltName(const LiteralValueBase& altName)
{
}


void
SubjectAlternativeNameExtension::commit2Config(CA& ca, Type type)
{
}

