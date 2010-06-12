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
		                      const std::list<blocxx::Int32>& numbers);

		String
		getOrganization() const;
		
		std::list<blocxx::Int32>
		getNoticeNumbers() const;

		virtual blocxx::String
		commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

		virtual bool
		valid() const;
		
		virtual std::vector<blocxx::String>
		verify() const;

		virtual std::vector<blocxx::String>
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
		setUserNoticeList(const std::list<UserNotice>& list);
		
		std::list<UserNotice>
		getUserNoticeList() const;
        
		virtual blocxx::String
		commit2Config(CA& ca, Type type, blocxx::UInt32 num) const;

		virtual bool
		valid() const;
		
		virtual std::vector<blocxx::String>
		verify() const;

		virtual std::vector<blocxx::String>
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const CertificatePolicy &l, const CertificatePolicy &r);
		
		friend bool
		operator<(const CertificatePolicy &l, const CertificatePolicy &r);

#endif

	private:
		blocxx::COWIntrusiveReference<CertificatePolicyImpl> m_impl;
		
		std::vector<blocxx::String>
		checkCpsURIs(const StringList& cpsURIs) const;
		
		std::vector<blocxx::String>
		checkNoticeList(const std::list<UserNotice>& list) const;
    };

	class CertificatePoliciesExt : public ExtensionBase {
	public:
		CertificatePoliciesExt();
		CertificatePoliciesExt(const std::list<CertificatePolicy>& policies);
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
		setPolicies(const std::list<CertificatePolicy>& policies);
		
		std::list<CertificatePolicy>
		getPolicies() const;

        virtual void
        commit2Config(CA& ca, Type type) const;
		
		virtual bool
		valid() const;
		
		virtual std::vector<blocxx::String>
		verify() const;

		virtual std::vector<blocxx::String>
		dump() const;

	private:
		blocxx::COWIntrusiveReference<CertificatePoliciesExtImpl> m_impl;
		
		std::vector<blocxx::String>
		checkPolicies(const std::list<CertificatePolicy>& pl) const;

    };

}

#endif // LIMAL_CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
