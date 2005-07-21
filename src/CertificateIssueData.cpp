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
#include  <blocxx/DateTime.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateIssueData::CertificateIssueData()
    : notBefore(0), notAfter(0),
      messageDigest(SHA1),
      extensions(X509v3CertificateIssueExtensions())
{
}

CertificateIssueData::CertificateIssueData(CAConfig* caConfig, Type type)
    : notBefore(0), notAfter(0), 
      messageDigest(SHA1),
      extensions(X509v3CertificateIssueExtensions(caConfig, type))
{
    notBefore = DateTime::getCurrent().get();

    UInt32 days = caConfig->getValue(type2Section(type, false), "default_days").toUInt32();
    DateTime dt = DateTime(notBefore);
    dt.addDays(days);
    notAfter    = dt.get();

    String md = caConfig->getValue(type2Section(type, false), "default_md");
    if(md.equalsIgnoreCase("sha1")) {
        messageDigest = SHA1;
    } else if(md.equalsIgnoreCase("md5")) {
        messageDigest = MD5;
    } else if(md.equalsIgnoreCase("mdc2")) {
        messageDigest = MDC2;
    } else {
        LOGIT_INFO("unsupported message digest: " << md);
        LOGIT_INFO("select default sha1.");
        messageDigest = SHA1;
    }
}

CertificateIssueData::CertificateIssueData(const CertificateIssueData& data)
    : notBefore(data.notBefore), notAfter(data.notAfter), 
      messageDigest(data.messageDigest),
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
    messageDigest = data.messageDigest;
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
CertificateIssueData::setMessageDigest(MD md)
{
    messageDigest = md;
}

MD 
CertificateIssueData::getMessageDigest() const
{
    return messageDigest;
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
    UInt32 t = (UInt32)((notAfter-notBefore)/(60*60*24));
    
    ca.getConfig()->setValue(type2Section(type, false), "default_days", String(t));
                        
    String md("sha1");
    switch(messageDigest) {
    case SHA1:
        md = "sha1";
        break;
    case MD5:
        md = "md5";
        break;
    case MDC2:
        md = "mdc2";
        break;
    }
    ca.getConfig()->setValue(type2Section(type, false), "default_md", md);

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

blocxx::StringArray
CertificateIssueData::dump() const
{
    StringArray result;
    result.append("CertificateIssueData::dump()");

    result.append("!CHANGING DATA! notBefore = " + String(notBefore));
    result.append("!CHANGING DATA! notAfter = " + String(notAfter));
    result.append("notAfter - notBefore (in days)= " + String((notAfter - notBefore)/86400));
    result.append("MessageDigest = " + String(messageDigest));
    result.appendArray(extensions.dump());

    return result;
}
