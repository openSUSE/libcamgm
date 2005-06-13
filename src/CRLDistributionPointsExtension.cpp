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

  File:       CRLDistributionPointsExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLDistributionPointsExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


CRLDistributionPointsExtension::CRLDistributionPointsExtension()
    : ExtensionBase()
{
}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(CA& ca, Type type)
    : ExtensionBase()
{
}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(const CRLDistributionPointsExtension& extension)
    : ExtensionBase()
{
}

CRLDistributionPointsExtension::~CRLDistributionPointsExtension()
{
}

CRLDistributionPointsExtension&
CRLDistributionPointsExtension::operator=(const CRLDistributionPointsExtension& extension)
{
    return *this;
}

void
CRLDistributionPointsExtension::setCRLDistributionPoints(blocxx::List<LiteralValueBase> dp)
{
    altNameList = dp;
}

blocxx::List<LiteralValueBase>
CRLDistributionPointsExtension::getCRLDistributionPoints() const
{
    return altNameList;
}

void
CRLDistributionPointsExtension::commit2Config(CA& ca, Type type)
{
}

