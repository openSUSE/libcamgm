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

  File:       X509v3RequestExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP
#define    CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/StringExtensions.hpp>
#include  <ca-mgm/BitExtensions.hpp>
#include  <ca-mgm/ExtendedKeyUsageExt.hpp>
#include  <ca-mgm/BasicConstraintsExtension.hpp>
#include  <ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <ca-mgm/SubjectAlternativeNameExtension.hpp>
#include <ca-mgm/PtrTypes.hpp>


namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class X509v3RequestExtsImpl;
	
    /**
     * @brief Collection of X509v3 extension for certificate requests
     *
     * This class includes a collection of X509v3 extension for 
     * certificate requests.
     */
	class X509v3RequestExts {

	public:
		X509v3RequestExts();
		X509v3RequestExts(CAConfig* caConfig, Type type);
		X509v3RequestExts(const X509v3RequestExts& extensions);
		virtual ~X509v3RequestExts();

#ifndef SWIG

		X509v3RequestExts&
		operator=(const X509v3RequestExts& extensions);

#endif
    	
		void
		setNsSslServerName(const NsSslServerNameExt &ext);
        
		NsSslServerNameExt
		getNsSslServerName() const;

		NsSslServerNameExt&
		nsSslServerName();

		void
		setNsComment(const NsCommentExt &ext);
        
		NsCommentExt
		getNsComment() const;

		NsCommentExt&
		nsComment();

		void
		setNsCertType(const NsCertTypeExt &ext);
        
		NsCertTypeExt
		getNsCertType() const;

		NsCertTypeExt&
		nsCertType();

		void
		setKeyUsage(const KeyUsageExt &ext);
        
		KeyUsageExt
		getKeyUsage() const;

		KeyUsageExt&
		keyUsage();

		void
		setBasicConstraints(const BasicConstraintsExt &ext);
        
		BasicConstraintsExt
		getBasicConstraints() const;

		BasicConstraintsExt&
		basicConstraints();

		void
		setExtendedKeyUsage(const ExtendedKeyUsageExt &ext);
        
		ExtendedKeyUsageExt
		getExtendedKeyUsage() const;

		ExtendedKeyUsageExt&
		extendedKeyUsage();

		void
		setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext);
        
		SubjectKeyIdentifierExt
		getSubjectKeyIdentifier() const;

		SubjectKeyIdentifierExt&
		subjectKeyIdentifier();

		void
		setSubjectAlternativeName(const SubjectAlternativeNameExt &ext);
        
		SubjectAlternativeNameExt
		getSubjectAlternativeName() const;

		SubjectAlternativeNameExt&
		subjectAlternativeName();

		void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	protected:
		ca_mgm::RWCOW_pointer<X509v3RequestExtsImpl> m_impl;

	};

}

#endif // CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP
