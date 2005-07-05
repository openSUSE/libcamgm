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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

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
    if(text.length() > 200) {
        LOGIT_ERROR("text to long");
        BLOCXX_THROW(limal::ValueException, "text to long");
    }
    
    explicitText = text;
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
    organization  = org;
    noticeNumbers = numbers;
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

blocxx::String
UserNotice::commit2Config(CA& ca, Type type, blocxx::UInt32 num) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid UserNotice object");
        BLOCXX_THROW(limal::ValueException, "invalid UserNotice object");
    }

    // These types are not supported by this object
    if(type == CRL        || type == Client_Req ||
       type == Server_Req || type == CA_Req      ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    // we need a User Notice section
    String sectionName = String("notice")+String(num);

    if(!explicitText.empty()) {
        ca.getConfig()->setValue(sectionName, "explicitText", explicitText);
    }

    if(!organization.empty()) {
        ca.getConfig()->setValue(sectionName, "organization", organization);

        String numbers;
        blocxx::List<blocxx::Int32>::const_iterator it = noticeNumbers.begin();
        for(;it != noticeNumbers.end(); ++it) {

            numbers += String(*it)+",";
        }
        ca.getConfig()->setValue(sectionName, "noticeNumbers", 
                                 numbers.erase(numbers.length()-2));
    }
    return ("@"+sectionName);
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
    
    if(!initOIDCheck().isValid(this->policyIdentifier)) {
        LOGIT_ERROR("invalid value for policyIdentifier" << this->policyIdentifier);
        BLOCXX_THROW(limal::ValueException ,
                     Format("invalid value for policyIdentifier: %1", this->policyIdentifier).c_str());
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
    if(!initOIDCheck().isValid(policyIdentifier)) {
        LOGIT_ERROR("invalid value for policyIdentifier" << policyIdentifier);
        BLOCXX_THROW(limal::ValueException,
                     Format("invalid value for policyIdentifier: %1", policyIdentifier).c_str());
    }
    
    this->policyIdentifier = policyIdentifier;
}

blocxx::String
CertificatePolicy::getPolicyIdentifier() const
{
    return policyIdentifier;
}

void
CertificatePolicy::setCpsURI(const StringList& cpsURI)
{
    StringArray r = checkCpsURIs(cpsURI); 
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->cpsURI = cpsURI;
}

StringList
CertificatePolicy::getCpsURI() const
{
    return cpsURI;
}

void
CertificatePolicy::setUserNoticeList(const blocxx::List<UserNotice>& list)
{
    StringArray r = checkNoticeList(list); 
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    noticeList = list;
}

blocxx::List<UserNotice>
CertificatePolicy::getUserNoticeList() const
{
    return noticeList;
}

blocxx::String
CertificatePolicy::commit2Config(CA& ca, Type type, blocxx::UInt32 num) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid CertificatePolicy object");
        BLOCXX_THROW(limal::ValueException, "invalid CertificatePolicy object");
    }

    // These types are not supported by this object
    if(type == CRL        || type == Client_Req ||
       type == Server_Req || type == CA_Req      ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(cpsURI.empty()) {
        // no practice statement; return directly the policyIdentifier
        return policyIdentifier;
    }
    // we need a policy section
    String sectionName = String("polsec")+String(num);

    ca.getConfig()->setValue(sectionName, "policyIdentifier", policyIdentifier);

    StringList::const_iterator it = cpsURI.begin();
    for(blocxx::UInt32 i = 1;it != cpsURI.end(); ++it, ++i) {

        ca.getConfig()->setValue(sectionName, "CPS."+String(i),(*it));
        
    }

    blocxx::List<UserNotice>::const_iterator nit = noticeList.begin();
    for(blocxx::UInt32 j = 1;nit != noticeList.end(); ++nit, ++j) {

        String n = (*nit).commit2Config(ca, type, j);
        ca.getConfig()->setValue(sectionName, "userNotice."+String(j),n);
    }

    return ("@"+sectionName);
}

bool
CertificatePolicy::valid() const
{
    if(policyIdentifier.empty() || !initOIDCheck().isValid(policyIdentifier)) {
        LOGIT_DEBUG("invalid value for policyIdentifier:" << policyIdentifier);
        return false;
    }

    StringArray r = checkCpsURIs(cpsURI);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    
    r = checkNoticeList(noticeList); ; 
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
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
    
    result.appendArray(checkCpsURIs(cpsURI));
    
    result.appendArray(checkNoticeList(noticeList)); 
    
    LOGIT_DEBUG_STRINGARRAY("CertificatePolicy::verify()", result);
    return result;
}

blocxx::StringArray
CertificatePolicy::checkCpsURIs(const StringList& cpsURIs) const
{
    StringArray result;
    ValueCheck  uriCheck = initURICheck();
    
    StringList::const_iterator it = cpsURIs.begin();
    for(;it != cpsURIs.end(); it++) {
        if(!uriCheck.isValid(*it)) {
            result.append(Format("invalid URI: %1", *it).toString());
        }
    }
    return result;
}

blocxx::StringArray
CertificatePolicy::checkNoticeList(const blocxx::List<UserNotice>& list) const
{
    StringArray result;
    blocxx::List<UserNotice>::const_iterator it = list.begin();
    for(;it != list.end(); it++) {
        result.appendArray((*it).verify());
    }
    return result;
}


// ###################################################################################

CertificatePoliciesExtension::CertificatePoliciesExtension()
    : ExtensionBase(), ia5org(false), policies(blocxx::List<CertificatePolicy>())
{}

CertificatePoliciesExtension::CertificatePoliciesExtension(const blocxx::List<CertificatePolicy>& policies)
    : ExtensionBase(), ia5org(false), policies(policies)
{
    StringArray r = checkPolicies(this->policies);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
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
    StringArray r = checkPolicies(policies);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->policies = policies;

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
CertificatePoliciesExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid CertificatePoliciesExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid CertificatePoliciesExtension object");
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

        if(ia5org) extString += "ia5org,";

        blocxx::List<CertificatePolicy>::const_iterator it = policies.begin();
        for(blocxx::UInt32 i = 0;it != policies.end(); ++it, ++i) {
            extString += (*it).commit2Config(ca, type, i) + ",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "certificatePolicies",
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "certificatePolicies");
    }
}

bool
CertificatePoliciesExtension::valid() const
{
    if(!isPresent()) return true;

    if(policies.empty()) {
        LOGIT_DEBUG("No policy set");
        return false;
    }
    StringArray r = checkPolicies(policies);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
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
    result.appendArray(checkPolicies(policies));
    
    LOGIT_DEBUG_STRINGARRAY("CertificatePoliciesExtension::verify()", result);
    
    return result;
}

blocxx::StringArray
CertificatePoliciesExtension::checkPolicies(const blocxx::List<CertificatePolicy>& pl) const
{
    StringArray result;
    blocxx::List<CertificatePolicy>::const_iterator it = pl.begin();
    for(;it != pl.end(); it++) {
        result.appendArray((*it).verify());
    }
    return result;
}
