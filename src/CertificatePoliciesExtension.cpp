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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


CertificatePolicy::CertificatePolicy()
{
}

CertificatePolicy::CertificatePolicy(const String& policyIdetifier)
{
}

CertificatePolicy::CertificatePolicy(const CertificatePolicy& policy)
{
}

CertificatePolicy::~CertificatePolicy()
{
}
       
CertificatePolicy&
CertificatePolicy::operator=(const CertificatePolicy& policy)
{
    return *this;
}

void
CertificatePolicy::setPolicyIdentifier(const String& policyIdentifier)
{
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
    this->cpsURI = cpsURI;
}

StringList
CertificatePolicy::getCpsURI() const
{
    return cpsURI;
}

void
CertificatePolicy::addCpsURI(const String& uri)
{
}

void
CertificatePolicy::setExplicitText(const String& text)
{
    explicitText = text;
}

blocxx::String
CertificatePolicy::getExplicitText() const
{
    return explicitText;
}

void
CertificatePolicy::setOrganization(const String& org)
{
    organization = org;
}

blocxx::String
CertificatePolicy::getOrganization() const
{
    return organization;
}


void
CertificatePolicy::setNoticeNumbers(const blocxx::List<blocxx::Int32>& numbers)
{
    noticeNumbers = numbers;
}

blocxx::List<blocxx::Int32>
CertificatePolicy::getNoticeNumbers()
{
    return noticeNumbers;
}

void
CertificatePolicy::addNoticeNumber(blocxx::Int32 num)
{
}


// ###################################################################################

CertificatePoliciesExtension::CertificatePoliciesExtension()
    : ExtensionBase()
{
}

CertificatePoliciesExtension::CertificatePoliciesExtension(CA& ca, Type type)
    : ExtensionBase()
{
}

CertificatePoliciesExtension::CertificatePoliciesExtension(const CertificatePoliciesExtension& extension)
    : ExtensionBase()
{
}

CertificatePoliciesExtension::~CertificatePoliciesExtension()
{
}

CertificatePoliciesExtension&
CertificatePoliciesExtension::operator=(const CertificatePoliciesExtension& extension)
{
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
    return ia5org;
}

void
CertificatePoliciesExtension::setPolicies(const blocxx::List<CertificatePolicy>& policies)
{
    this->policies = policies;
}

blocxx::List<CertificatePolicy>
CertificatePoliciesExtension::getPolicies() const
{
    return policies;
}

void
CertificatePoliciesExtension::addPolicy(const CertificatePolicy& policy)
{
}

void
CertificatePoliciesExtension::commit2Config(CA& ca, Type type)
{
}
