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

  File:       X509v3CRLExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_X509V3_CRL_EXTENSIONS_HPP
#define    CA_MGM_X509V3_CRL_EXTENSIONS_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/AuthorityKeyIdentifierExtension.hpp>
#include  <ca-mgm/IssuerAlternativeNameExtension.hpp>
#include <ca-mgm/PtrTypes.hpp>


namespace CA_MGM_NAMESPACE {

	class X509v3CRLExtsImpl;
	
    /**
     * @brief Collection of X509v3 extension for presenting CRLs
     *
     * This class includes a collection of X509v3 extension for presenting CRLs
     * (Read-only data representation)
     */
	class X509v3CRLExts {
	public:
		X509v3CRLExts(const X509v3CRLExts& extensions);
		virtual ~X509v3CRLExts();

#ifndef SWIG

		X509v3CRLExts&
		operator=(const X509v3CRLExts& extensions);

#endif
		
		AuthorityKeyIdentifierExt
		getAuthorityKeyIdentifier() const;
        
		IssuerAlternativeNameExt
		getIssuerAlternativeName() const;

		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;
        
	protected:
		ca_mgm::RWCOW_pointer<X509v3CRLExtsImpl> m_impl;
    	
		X509v3CRLExts();
	};

}

#endif // CA_MGM_X509V3_CRL_EXTENSIONS_HPP
