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
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLDistributionPointsExtension::CRLDistributionPointsExtension()
    : ExtensionBase(), altNameList(blocxx::List<LiteralValueBase>())
{}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(CA& ca, Type type)
    : ExtensionBase(), altNameList(blocxx::List<LiteralValueBase>())
{}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(const CRLDistributionPointsExtension& extension)
    : ExtensionBase(), altNameList(extension.altNameList)
{}

CRLDistributionPointsExtension::~CRLDistributionPointsExtension()
{}

CRLDistributionPointsExtension&
CRLDistributionPointsExtension::operator=(const CRLDistributionPointsExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    altNameList = extension.altNameList;

    return *this;
}

void
CRLDistributionPointsExtension::setCRLDistributionPoints(blocxx::List<LiteralValueBase> dp)
{
    if(dp.empty()) {
        LOGIT_ERROR("invalid value for CRLDistributionPointsExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for CRLDistributionPointsExtension");
    }
    blocxx::List<LiteralValueBase>::const_iterator it = dp.begin();
    for(;it != dp.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_ERROR("invalid literal value for CRLDistributionPointsExtension");
            BLOCXX_THROW(limal::ValueException, 
                         "invalid literal value for CRLDistributionPointsExtension");
        }
    }
    
    altNameList = dp;
}

blocxx::List<LiteralValueBase>
CRLDistributionPointsExtension::getCRLDistributionPoints() const
{
    if(!isPresent()) {
        LOGIT_ERROR("CRLDistributionPointsExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "CRLDistributionPointsExtension is not present");
    }
    return altNameList;
}

void
CRLDistributionPointsExtension::commit2Config(CA& ca, Type type)
{
}

bool
CRLDistributionPointsExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return CRLDistributionPointsExtension::valid() is true");
        return true;
    }

    if(altNameList.empty()) return false;

    blocxx::List<LiteralValueBase>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return CRLDistributionPointsExtension::valid() is false");
            return false;
        }
    }
    LOGIT_DEBUG("return CRLDistributionPointsExtension::valid() is true");
    return true;
}

blocxx::StringArray
CRLDistributionPointsExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(altNameList.empty()) {
        result.append(String("No value for CRLDistributionPointsExtension."));
    }

    blocxx::List<LiteralValueBase>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("CRLDistributionPointsExtension::verify()", result);
    return result;
}

