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
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class UserNoticeImpl;
	class CertificatePolicyImpl;
	class CertificatePoliciesExtImpl;
	
	class UserNotice {
    public:
		UserNotice();
		UserNotice(const UserNotice& notice);
		virtual ~UserNotice();

#ifndef SWIG
    	
		UserNotice&
		operator=(const UserNotice& notice);

#endif
		
		void
		initWithSection(CAConfig* caConfig, Type type, const String& sectionName);

		void
		setExplicitText(const String& text);
		
		String
		getExplicitText() const;

		void
		setOrganizationNotice(const String& org, 
		                      const blocxx::List<blocxx::Int32>& numbers);

		String
		getOrganization() const;
		
		blocxx::List<blocxx::Int32>
		getNoticeNumbers() const;

		virtual blocxx::String
		commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

		virtual bool
		valid() const;
		
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const UserNotice &l, const UserNotice &r);
		
		friend bool
		operator<(const UserNotice &l, const UserNotice &r);

#endif

	private:
		blocxx::COWIntrusiveReference<UserNoticeImpl> m_impl;
    	
	};

	class CertificatePolicy {
	public:
		CertificatePolicy();
		CertificatePolicy(const String& policyIdetifier);
		CertificatePolicy(const CertificatePolicy& policy);
		virtual ~CertificatePolicy();
		
#ifndef SWIG

		CertificatePolicy&
		operator=(const CertificatePolicy& policy);

#endif

		void
		initWithSection(CAConfig* caConfig, Type type, const String& sectionName);

		void
		setPolicyIdentifier(const String& policyIdentifier);
		
		String
		getPolicyIdentifier() const;

		void
		setCpsURI(const StringList& cpsURI);
		
		StringList
		getCpsURI() const;
		
		void
		setUserNoticeList(const blocxx::List<UserNotice>& list);
		
		blocxx::List<UserNotice>
		getUserNoticeList() const;
        
		virtual blocxx::String
		commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

		virtual bool
		valid() const;
		
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const CertificatePolicy &l, const CertificatePolicy &r);
		
		friend bool
		operator<(const CertificatePolicy &l, const CertificatePolicy &r);

#endif

	private:
		blocxx::COWIntrusiveReference<CertificatePolicyImpl> m_impl;
		
		blocxx::StringArray
		checkCpsURIs(const StringList& cpsURIs) const;
		
		blocxx::StringArray
		checkNoticeList(const blocxx::List<UserNotice>& list) const;
    };

	class CertificatePoliciesExt : public ExtensionBase {
	public:
		CertificatePoliciesExt();
		CertificatePoliciesExt(const blocxx::List<CertificatePolicy>& policies);
		CertificatePoliciesExt(CAConfig* caConfig, Type type);
		CertificatePoliciesExt(const CertificatePoliciesExt& extension);
		virtual ~CertificatePoliciesExt();
		
#ifndef SWIG

		CertificatePoliciesExt&
		operator=(const CertificatePoliciesExt& extension);

#endif

		void
		enableIA5org(bool ia5org = true);
		
		bool
		isIA5orgEnabled() const;
		
		void
		setPolicies(const blocxx::List<CertificatePolicy>& policies);
		
		blocxx::List<CertificatePolicy>
		getPolicies() const;

        virtual void
        commit2Config(CA& ca, Type type) const;
		
		virtual bool
		valid() const;
		
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<CertificatePoliciesExtImpl> m_impl;
		
		blocxx::StringArray
		checkPolicies(const blocxx::List<CertificatePolicy>& pl) const;

    };

}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
