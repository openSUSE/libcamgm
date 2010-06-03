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

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

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
        
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<X509v3CRLGenerationExtsImpl> m_impl;
    	
	};
}
#endif //LIMAL_CA_MGM_X509V3_CRL_GENERATION_EXTENSIONS_HPP
