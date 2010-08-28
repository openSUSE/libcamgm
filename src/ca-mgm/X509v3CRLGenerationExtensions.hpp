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

  File:       X509v3CRLGenerationExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
#include  <ca-mgm/IssuerAlternativeNameExtension.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE
{

	class CA;
	class CAConfig;
	class X509v3CRLGenerationExtsImpl;
	
    /**
     * @brief Collection of X509v3 extension for generating CRLs
     *
     * This class includes a collection of X509v3 extension for generating CRLs
     */
	class X509v3CRLGenerationExts {
	public:
		X509v3CRLGenerationExts();
		X509v3CRLGenerationExts(CAConfig* caConfig, Type type);
		X509v3CRLGenerationExts(const X509v3CRLGenerationExts& extensions);
		virtual ~X509v3CRLGenerationExts();

#ifndef SWIG

		X509v3CRLGenerationExts&
		operator=(const X509v3CRLGenerationExts& extension);

#endif
		
		void
		setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext);
        
		AuthorityKeyIdentifierGenerateExt
		getAuthorityKeyIdentifier() const;
        
		AuthorityKeyIdentifierGenerateExt&
		authorityKeyIdentifier();
        
		void
		setIssuerAlternativeName(const IssuerAlternativeNameExt &ext);
        
		IssuerAlternativeNameExt
		getIssuerAlternativeName() const;
		
		IssuerAlternativeNameExt&
		issuerAlternativeName();
        
		void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	private:
		ca_mgm::RWCOW_pointer<X509v3CRLGenerationExtsImpl> m_impl;
    	
	};
}
#endif //LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP
