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

  File:       CRLGenerationData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CRLGenerationData.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLGenerationData::CRLGenerationData()
    : crlHours(0), extensions(X509v3CRLGenerationExtensions())
{
}

CRLGenerationData::CRLGenerationData(CA& ca, Type type)
    : crlHours(0), extensions(X509v3CRLGenerationExtensions())
{
}

CRLGenerationData::CRLGenerationData(blocxx::UInt32 hours, 
                                     const X509v3CRLGenerationExtensions& ext)
    : crlHours(hours), extensions(ext)
{
    StringArray r = this->verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

CRLGenerationData::CRLGenerationData(const CRLGenerationData& data)
    : crlHours(data.crlHours), extensions(data.extensions)
{}

CRLGenerationData::~CRLGenerationData()
{}
       
CRLGenerationData&
CRLGenerationData::operator=(const CRLGenerationData& data)
{
    if(this == &data) return *this;
    
    crlHours   = data.crlHours;
    extensions = data.extensions;
    
    return *this;
}

void
CRLGenerationData::setCRLLifeTime(blocxx::UInt32 hours)
{
    blocxx::UInt32 oldH = crlHours;

    crlHours = hours;

    StringArray r = this->verify();
    if(!r.empty()) {
        crlHours = oldH;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::UInt32
CRLGenerationData::getCRLLifeTime() const
{
    return crlHours;
}

void
CRLGenerationData::setExtensions(const X509v3CRLGenerationExtensions& ext)
{
    StringArray r = ext.verify();
        
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

X509v3CRLGenerationExtensions
CRLGenerationData::getExtensions() const
{
    return extensions;
}

void
CRLGenerationData::commit2Config(CA& ca, Type type)
{
}

bool
CRLGenerationData::valid() const
{
    if(crlHours == 0) {
        LOGIT_DEBUG("invalid crlhours: " << crlHours);
        return false;
    }
    return extensions.valid();
}

blocxx::StringArray
CRLGenerationData::verify() const
{
    StringArray result;

    if(crlHours == 0) {
        result.append(Format("invalid crlhours: %1", crlHours).toString());
    }
    result.appendArray(extensions.verify());

    LOGIT_DEBUG_STRINGARRAY("CRLGenerationData::verify()", result);

    return result;
}

