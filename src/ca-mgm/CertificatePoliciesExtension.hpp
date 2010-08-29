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
#ifndef    CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
#define    CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/ExtensionBase.hpp>
#include <ca-mgm/PtrTypes.hpp>

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
		initWithSection(CAConfig* caConfig, Type type, const std::string& sectionName);

		void
		setExplicitText(const std::string& text);

		std::string
		getExplicitText() const;

		void
		setOrganizationNotice(const std::string& org,
		                      const std::list<int32_t>& numbers);

		std::string
		getOrganization() const;

		std::list<int32_t>
		getNoticeNumbers() const;

		virtual std::string
		commit2Config(CA& ca, Type type, uint32_t num) const;

		virtual bool
		valid() const;

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const UserNotice &l, const UserNotice &r);

		friend bool
		operator<(const UserNotice &l, const UserNotice &r);

#endif

	private:
		ca_mgm::RWCOW_pointer<UserNoticeImpl> m_impl;

	};

	class CertificatePolicy {
	public:
		CertificatePolicy();
		CertificatePolicy(const std::string& policyIdetifier);
		CertificatePolicy(const CertificatePolicy& policy);
		virtual ~CertificatePolicy();

#ifndef SWIG

		CertificatePolicy&
		operator=(const CertificatePolicy& policy);

#endif

		void
		initWithSection(CAConfig* caConfig, Type type, const std::string& sectionName);

		void
		setPolicyIdentifier(const std::string& policyIdentifier);

		std::string
		getPolicyIdentifier() const;

		void
		setCpsURI(const StringList& cpsURI);

		StringList
		getCpsURI() const;

		void
		setUserNoticeList(const std::list<UserNotice>& list);

		std::list<UserNotice>
		getUserNoticeList() const;

		virtual std::string
		commit2Config(CA& ca, Type type, uint32_t num) const;

		virtual bool
		valid() const;

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const CertificatePolicy &l, const CertificatePolicy &r);

		friend bool
		operator<(const CertificatePolicy &l, const CertificatePolicy &r);

#endif

	private:
		ca_mgm::RWCOW_pointer<CertificatePolicyImpl> m_impl;

		std::vector<std::string>
		checkCpsURIs(const StringList& cpsURIs) const;

		std::vector<std::string>
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

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	private:
		ca_mgm::RWCOW_pointer<CertificatePoliciesExtImpl> m_impl;

		std::vector<std::string>
		checkPolicies(const std::list<CertificatePolicy>& pl) const;

    };

}

#endif // CA_MGM_CERTIFICATE_POLICIES_EXTENSION_HPP
