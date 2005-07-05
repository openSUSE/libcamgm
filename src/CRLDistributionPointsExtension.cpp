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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLDistributionPointsExtension::CRLDistributionPointsExtension()
    : ExtensionBase(), altNameList(blocxx::List<LiteralValue>())
{}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(CA& ca, Type type)
    : ExtensionBase(), altNameList(blocxx::List<LiteralValue>())
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
CRLDistributionPointsExtension::setCRLDistributionPoints(blocxx::List<LiteralValue> dp)
{
    StringArray r = checkLiteralValueList(dp);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    altNameList = dp;
    setPresent(true);
}

blocxx::List<LiteralValue>
CRLDistributionPointsExtension::getCRLDistributionPoints() const
{
    if(!isPresent()) {
        LOGIT_ERROR("CRLDistributionPointsExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "CRLDistributionPointsExtension is not present");
    }
    return altNameList;
}

void
CRLDistributionPointsExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid CRLDistributionPointsExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid CRLDistributionPointsExtension object");
    }

    // These types are not supported by this object
    if(type == CRL        || type == Client_Req ||
       type == Server_Req || type == CA_Req      ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";

        blocxx::List<LiteralValue>::const_iterator it = altNameList.begin();
        for(;it != altNameList.end(); ++it) {
            extString += (*it).toString()+",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "crlDistributionPoints",
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "crlDistributionPoints");
    }
}

bool
CRLDistributionPointsExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return CRLDistributionPointsExtension::valid() is true");
        return true;
    }

    if(altNameList.empty()) return false;

    StringArray r = checkLiteralValueList(altNameList);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
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
    result.appendArray(checkLiteralValueList(altNameList));
    
    LOGIT_DEBUG_STRINGARRAY("CRLDistributionPointsExtension::verify()", result);
    return result;
}

