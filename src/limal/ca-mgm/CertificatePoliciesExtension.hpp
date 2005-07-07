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

  File:       CertificatePoliciesExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class UserNotice {
    public:
        UserNotice();
        UserNotice(const UserNotice& notice);
        virtual ~UserNotice();

        UserNotice& operator=(const UserNotice& notice);

        void                initWithSection(CA& ca, Type type, const String& sectionName);

        void                setExplicitText(const String& text);
        String              getExplicitText() const;

        void                setOrganizationNotice(const String& org, 
                                                  const blocxx::List<blocxx::Int32>& numbers);

        String                      getOrganization() const;
        blocxx::List<blocxx::Int32> getNoticeNumbers();

        virtual blocxx::String      commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        String              explicitText;      // max 200 characters

        // The organization and noticeNumbers options
        // (if included) must BOTH be present.

        String                      organization;      // max 200 characters 
        blocxx::List<blocxx::Int32> noticeNumbers;

    };

    class CertificatePolicy {
    public:
        CertificatePolicy();
        CertificatePolicy(const String& policyIdetifier);
        CertificatePolicy(const CertificatePolicy& policy);
        virtual ~CertificatePolicy();
        
        CertificatePolicy& operator=(const CertificatePolicy& policy);

        void                initWithSection(CA& ca, Type type, const String& sectionName);

        void                setPolicyIdentifier(const String& policyIdentifier);
        String              getPolicyIdentifier() const;

        void                setCpsURI(const StringList& cpsURI);
        StringList          getCpsURI() const;

        void                     setUserNoticeList(const blocxx::List<UserNotice>& list);
        blocxx::List<UserNotice> getUserNoticeList() const;
        
        virtual blocxx::String   commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        String                   policyIdentifier;  // required
        StringList               cpsURI;            // Certification Practice Statement

        blocxx::List<UserNotice> noticeList;

        blocxx::StringArray      checkCpsURIs(const StringList& cpsURIs) const;
        blocxx::StringArray      checkNoticeList(const blocxx::List<UserNotice>& list) const;
        
    };

    class CertificatePoliciesExtension : public ExtensionBase {
    public:
        CertificatePoliciesExtension();
        CertificatePoliciesExtension(const blocxx::List<CertificatePolicy>& policies);
        CertificatePoliciesExtension(CA& ca, Type type);
        CertificatePoliciesExtension(const CertificatePoliciesExtension& extension);
        virtual ~CertificatePoliciesExtension();

        CertificatePoliciesExtension& operator=(const CertificatePoliciesExtension& extension);

        void                    enableIA5org(bool ia5org = true);
        bool                    isIA5orgEnabled() const;

        void                    setPolicies(const blocxx::List<CertificatePolicy>& policies);
        blocxx::List<CertificatePolicy> getPolicies() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                    valid() const;
        virtual blocxx::StringArray     verify() const;

        virtual blocxx::StringArray  dump() const;

    private:

        bool ia5org;
        blocxx::List<CertificatePolicy> policies;

        blocxx::StringArray             checkPolicies(const blocxx::List<CertificatePolicy>& pl) const;

    };

}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
