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

  File:       CertificateIssueData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CertificateIssueData.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateIssueData::CertificateIssueData()
    : notBefore(0), notAfter(0), 
      extensions(X509v3CertificateIssueExtensions())
{
}

CertificateIssueData::CertificateIssueData(CA& ca, Type type)
    : notBefore(0), notAfter(0), 
      extensions(X509v3CertificateIssueExtensions())
{
}

CertificateIssueData::CertificateIssueData(const CertificateIssueData& data)
    : notBefore(data.notBefore), notAfter(data.notAfter), 
      extensions(data.extensions)
{
}

CertificateIssueData::~CertificateIssueData()
{}

CertificateIssueData&
CertificateIssueData::operator=(const CertificateIssueData& data)
{
    if(this == &data) return *this;
    
    notBefore     = data.notBefore;
    notAfter      = data.notAfter;
    extensions    = data.extensions;
    
    return *this;
}

void
CertificateIssueData::setCertifiyPeriode(time_t start, time_t end)
{
    notBefore = start;
    notAfter  = end;
}

time_t
CertificateIssueData::getStartDate() const
{
    return notBefore;
}

time_t
CertificateIssueData::getEndDate() const
{
    return notAfter;
}

void
CertificateIssueData::setExtensions(const X509v3CertificateIssueExtensions& ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

X509v3CertificateIssueExtensions
CertificateIssueData::getExtensions() const
{
    return extensions;
}

void
CertificateIssueData::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid CertificateIssueData object");
        BLOCXX_THROW(limal::ValueException, "invalid CertificateIssueData object");
    }
    // These types are not supported by this object
    if(type == CRL        || type == Client_Req ||
       type == Server_Req || type == CA_Req         ) {
        
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    extensions.commit2Config(ca, type);
}

bool
CertificateIssueData::valid() const
{
    if(notBefore == 0) {
        LOGIT_DEBUG("invalid notBefore:" << notBefore);
        return false;
    }
    if(notAfter <= notBefore) {
        LOGIT_DEBUG("invalid notAfter:" << notAfter);
        return false;
    }

    if(!extensions.valid()) return false;
    
    return true;
}

blocxx::StringArray
CertificateIssueData::verify() const
{
    StringArray result;

    if(notBefore == 0) {
        result.append(Format("invalid notBefore: %1", notBefore).toString());
    }
    if(notAfter <= notBefore) {
        result.append(Format("invalid notAfter: %1", notAfter).toString());
    }

    result.appendArray(extensions.verify());
    
    LOGIT_DEBUG_STRINGARRAY("CertificateIssueData::verify()", result);

    return result;
}

