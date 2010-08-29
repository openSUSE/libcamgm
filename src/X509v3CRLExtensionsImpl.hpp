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

  File:       X509v3CertificateExtensionsImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_X509V3_CRL_EXTS_IMPL_HPP
#define    CA_MGM_X509V3_CRL_EXTS_IMPL_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>



namespace CA_MGM_NAMESPACE {

class X509v3CRLExtsImpl
{
public:
	X509v3CRLExtsImpl()
		: authorityKeyIdentifier(AuthorityKeyIdentifierExt()),
		issuerAlternativeName(IssuerAlternativeNameExt())
	{}

	X509v3CRLExtsImpl(const X509v3CRLExtsImpl& impl)
		: authorityKeyIdentifier(impl.authorityKeyIdentifier)
		, issuerAlternativeName(impl.issuerAlternativeName)
	{}

	~X509v3CRLExtsImpl() {}

	X509v3CRLExtsImpl* clone() const
	{
		return new X509v3CRLExtsImpl(*this);
	}

	AuthorityKeyIdentifierExt authorityKeyIdentifier;
	IssuerAlternativeNameExt  issuerAlternativeName;
};
}
#endif     /* CA_MGM_X509V3_CRL_EXTS_IMPL_HPP */
