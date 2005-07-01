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

  File:       CertificatePoliciesExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/CertificatePoliciesExtension.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

inline static ValueCheck initOIDCheck() {
    ValueCheck checkOID =
        ValueCheck(new ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));
    
    return checkOID;
}

inline static ValueCheck initURICheck() {
    ValueCheck checkURI =
        ValueCheck(new ValuePosixRECheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\\\?([^#]*))?(#(.*))?"  ));

    return checkURI;
}

UserNotice::UserNotice()
    : explicitText(String()), organization(String()),
      noticeNumbers(blocxx::List<blocxx::Int32>())
{
}

UserNotice::UserNotice(const UserNotice& notice)
    : explicitText(notice.explicitText), organization(notice.organization),
      noticeNumbers(notice.noticeNumbers)
{
}

UserNotice::~UserNotice()
{}

UserNotice&
UserNotice::operator=(const UserNotice& notice)
{
    if(this == &notice) return *this;
    
    explicitText     = notice.explicitText;
    organization     = notice.organization;
    noticeNumbers    = notice.noticeNumbers;
    
    return *this;
}

void
UserNotice::setExplicitText(const String& text)
{
    String oldText = explicitText;

    explicitText = text;

    StringArray r = this->verify();
    if(!r.empty()) {
        explicitText = oldText;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::String
UserNotice::getExplicitText() const
{
    return explicitText;
}

void
UserNotice::setOrganizationNotice(const String& org, 
                                  const blocxx::List<blocxx::Int32>& numbers)
{
    String                      oldOrg = organization;
    blocxx::List<blocxx::Int32> oldNum = noticeNumbers;

    organization  = org;
    noticeNumbers = numbers;

    StringArray r = this->verify();
    if(!r.empty()) {
        organization  = oldOrg;
        noticeNumbers = oldNum;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::String
UserNotice::getOrganization() const
{
    return organization;
}

blocxx::List<blocxx::Int32>
UserNotice::getNoticeNumbers()
{
    return noticeNumbers;
}

bool
UserNotice::valid() const
{
    if(explicitText.length() > 200) {
        LOGIT_DEBUG("explicitText to long");
        return false;
    }

    if((organization.empty() && !noticeNumbers.empty()) ||
       (!organization.empty() && noticeNumbers.empty()))   {
        LOGIT_DEBUG("organization and noticeNumbers must both present or absent");
        return false;
    }
    return true;
}

blocxx::StringArray
UserNotice::verify() const
{
    StringArray result;

    if(explicitText.length() > 200) {
        result.append("explicitText to long");
    }

    if((organization.empty() && !noticeNumbers.empty()) ||
       (!organization.empty() && noticeNumbers.empty()))   {
        result.append("organization and noticeNumbers must both present or absent");
    }
    LOGIT_DEBUG_STRINGARRAY("UserNotice::verify()", result);
    return result;
}

// ###########################################################################

CertificatePolicy::CertificatePolicy()
    : policyIdentifier(String()), cpsURI(StringList()), 
      noticeList(blocxx::List<UserNotice>())
{
}

CertificatePolicy::CertificatePolicy(const String& policyIdetifier)
    : policyIdentifier(policyIdetifier), cpsURI(StringList()), 
      noticeList(blocxx::List<UserNotice>())
{
    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

CertificatePolicy::CertificatePolicy(const CertificatePolicy& policy)
    : policyIdentifier(policy.policyIdentifier), cpsURI(policy.cpsURI),
      noticeList(policy.noticeList)
{}

CertificatePolicy::~CertificatePolicy()
{}
       
CertificatePolicy&
CertificatePolicy::operator=(const CertificatePolicy& policy)
{
    if(this == &policy) return *this;
    
    policyIdentifier = policy.policyIdentifier;                              
    cpsURI           = policy.cpsURI;
    noticeList       = policy.noticeList;
    
    return *this;
}

void
CertificatePolicy::setPolicyIdentifier(const String& policyIdentifier)
{
    String oldPI = this->policyIdentifier;
    
    this->policyIdentifier = policyIdentifier;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->policyIdentifier = oldPI;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::String
CertificatePolicy::getPolicyIdentifier() const
{
    return policyIdentifier;
}

void
CertificatePolicy::setCpsURI(const StringList& cpsURI)
{
    StringList oldCpsURI = this->cpsURI;
    
    this->cpsURI = cpsURI;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->cpsURI = oldCpsURI;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

StringList
CertificatePolicy::getCpsURI() const
{
    return cpsURI;
}

void
CertificatePolicy::setUserNoticeList(const blocxx::List<UserNotice>& list)
{
    blocxx::List<UserNotice> oldList = noticeList;
    
    noticeList = list;

    StringArray r = this->verify();
    if(!r.empty()) {
        noticeList = oldList;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::List<UserNotice>
CertificatePolicy::getUserNoticeList() const
{
    return noticeList;
}

bool
CertificatePolicy::valid() const
{
    ValueCheck oidCheck = initOIDCheck();
    
    if(policyIdentifier.empty() || !oidCheck.isValid(policyIdentifier)) {
        LOGIT_DEBUG("invalid value for policyIdentifier:" << policyIdentifier);
        return false;
    }

    ValueCheck uriCheck = initURICheck();
    StringList::const_iterator uit = cpsURI.begin();
    for(;uit != cpsURI.end(); uit++) {
        if(!uriCheck.isValid(*uit)) {
            LOGIT_DEBUG("invalid URI:" << *uit);
            return false;
        }
    }

    blocxx::List<UserNotice>::const_iterator it = noticeList.begin();
    for(;it != noticeList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return CertificatePolicy::valid() is false");
            return false;
        }
    }
    return true;
}

blocxx::StringArray
CertificatePolicy::verify() const
{
    StringArray result;

    ValueCheck oidCheck = initOIDCheck();
    
    if(policyIdentifier.empty() || !oidCheck.isValid(policyIdentifier)) {
        result.append(Format("invalid value for policyIdentifier: %1", policyIdentifier).toString());
    }

    ValueCheck uriCheck = initURICheck();
    StringList::const_iterator uit = cpsURI.begin();
    for(;uit != cpsURI.end(); uit++) {
        if(!uriCheck.isValid(*uit)) {
            result.append(Format("invalid URI: %1", *uit).toString());
        }
    }
    
    blocxx::List<UserNotice>::const_iterator it = noticeList.begin();
    for(;it != noticeList.end(); it++) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("CertificatePolicy::verify()", result);
    return result;
}

// ###################################################################################

CertificatePoliciesExtension::CertificatePoliciesExtension()
    : ExtensionBase(), ia5org(false), policies(blocxx::List<CertificatePolicy>())
{}

CertificatePoliciesExtension::CertificatePoliciesExtension(const blocxx::List<CertificatePolicy>& policies)
    : ExtensionBase(), ia5org(false), policies(policies)
{
    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    setPresent(true);
}

CertificatePoliciesExtension::CertificatePoliciesExtension(CA& ca, Type type)
    : ExtensionBase(), ia5org(false), policies(blocxx::List<CertificatePolicy>())
{
}

CertificatePoliciesExtension::CertificatePoliciesExtension(const CertificatePoliciesExtension& extension)
    : ExtensionBase(), ia5org(extension.ia5org), policies(extension.policies)
{}

CertificatePoliciesExtension::~CertificatePoliciesExtension()
{}

CertificatePoliciesExtension&
CertificatePoliciesExtension::operator=(const CertificatePoliciesExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    
    ia5org = extension.ia5org;
    policies = extension.policies;

    return *this;
}

void
CertificatePoliciesExtension::enableIA5org(bool ia5org)
{
    this->ia5org = ia5org;
}

bool
CertificatePoliciesExtension::isIA5orgEnabled() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "CertificatePoliciesExtension is not present");
    }
    return ia5org;
}

void
CertificatePoliciesExtension::setPolicies(const blocxx::List<CertificatePolicy>& policies)
{
    blocxx::List<CertificatePolicy> oldPolicies = policies;
    
    this->policies = policies;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->policies   = oldPolicies;

        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    setPresent(true);
}

blocxx::List<CertificatePolicy>
CertificatePoliciesExtension::getPolicies() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "CertificatePoliciesExtension is not present");
    }
    return policies;
}


void
CertificatePoliciesExtension::commit2Config(CA& ca, Type type)
{
}

bool
CertificatePoliciesExtension::valid() const
{
    if(!isPresent()) return true;

    if(policies.empty()) {
        LOGIT_DEBUG("No policy set");
        return false;
    }
    blocxx::List<CertificatePolicy>::const_iterator it = policies.begin();
    for(;it != policies.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return CertificatePoliciesExtension::valid() is false");
            return false;
        }
    }
    return true;
}

blocxx::StringArray
CertificatePoliciesExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(policies.empty()) {
        result.append("No policy set");
    }
    blocxx::List<CertificatePolicy>::const_iterator it = policies.begin();
    for(;it != policies.end(); it++) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("CertificatePoliciesExtension::verify()", result);
    
    return result;
}
