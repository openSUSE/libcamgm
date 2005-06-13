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

  File:       IssuerAlternativeNameExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(bool copyIssuer, 
                                                               const blocxx::List<LiteralValueBase> &alternativeNameList)
    :ExtensionBase()
{
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(CA& ca, Type type)
    :ExtensionBase()
{
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(const IssuerAlternativeNameExtension& extension)
    :ExtensionBase()
{
}

IssuerAlternativeNameExtension::~IssuerAlternativeNameExtension()
{
}

IssuerAlternativeNameExtension&
IssuerAlternativeNameExtension::operator=(const IssuerAlternativeNameExtension& extension)
{
    return *this;
}

void
IssuerAlternativeNameExtension::setCopyIssuer(bool copyIssuer)
{
    issuerCopy = copyIssuer;
}

bool
IssuerAlternativeNameExtension::getCopyIssuer() const
{
    return issuerCopy;
}

void
IssuerAlternativeNameExtension::setAlternativeNameList(const blocxx::List<LiteralValueBase> &alternativeNameList)
{
    altNameList = alternativeNameList;
}

blocxx::List<LiteralValueBase>
IssuerAlternativeNameExtension::getAlternativeNameList() const
{
    return altNameList;
}

void
IssuerAlternativeNameExtension::addIssuerAltName(const LiteralValueBase& altName)
{
}


void
IssuerAlternativeNameExtension::commit2Config(CA& ca, Type type)
{
}

