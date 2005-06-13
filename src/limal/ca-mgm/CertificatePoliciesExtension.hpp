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

    class CertificatePolicy {
    public:
        CertificatePolicy();
        CertificatePolicy(const String& policyIdetifier);
        CertificatePolicy(const CertificatePolicy& policy);
        virtual ~CertificatePolicy();
        
        CertificatePolicy& operator=(const CertificatePolicy& policy);

        void                setPolicyIdentifier(const String& policyIdentifier);
        String              getPolicyIdentifier() const;

        void                setCpsURI(const StringList& cpsURI);
        StringList          getCpsURI() const;
        void                addCpsURI(const String& uri);

        void                setExplicitText(const String& text);
        String              getExplicitText() const;

        void                setOrganization(const String& org);
        String              getOrganization() const;

        void                setNoticeNumbers(const blocxx::List<blocxx::Int32>& numbers);
        blocxx::List<blocxx::Int32> getNoticeNumbers();
        void                addNoticeNumber(blocxx::Int32 num);

    private:
        String              policyIdentifier;  // required
        StringList          cpsURI;            // Certification Practice Statement
        String              explicitText;      // max 200 characters

        // The organization and noticeNumbers options
        // (if included) must BOTH be present.

        String              organization;      // max 200 characters 
        blocxx::List<blocxx::Int32> noticeNumbers;

    };

    class CertificatePoliciesExtension : public ExtensionBase {
    public:
        CertificatePoliciesExtension();
        CertificatePoliciesExtension(CA& ca, Type type);
        CertificatePoliciesExtension(const CertificatePoliciesExtension& extension);
        virtual ~CertificatePoliciesExtension();

        CertificatePoliciesExtension& operator=(const CertificatePoliciesExtension& extension);

        void                    enableIA5org(bool ia5org = true);
        bool                    isIA5orgEnabled() const;

        void                    setPolicies(const blocxx::List<CertificatePolicy>& policies);
        blocxx::List<CertificatePolicy> getPolicies() const;
        void                    addPolicy(const CertificatePolicy& policy);

        virtual void commit2Config(CA& ca, Type type);
    private:

        bool ia5org;
        blocxx::List<CertificatePolicy> policies;

    };

}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
