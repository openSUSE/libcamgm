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

  File:       X509v3CRLExtensions_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_PRIV_HPP
#define    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CRLExtensions.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class X509v3CRLExtensions_Priv : public X509v3CRLExtensions {
    public:
        X509v3CRLExtensions_Priv();
        X509v3CRLExtensions_Priv(STACK_OF(X509_EXTENSION) *extensions);
        X509v3CRLExtensions_Priv(const X509v3CRLExtensions_Priv& extensions);
        virtual ~X509v3CRLExtensions_Priv();

        void     setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext);
        void     setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext);

    private:

        X509v3CRLExtensions_Priv& operator=(const X509v3CRLExtensions_Priv& extensions);

        void parseIssuerAlternativeNameExtension(STACK_OF(X509_EXTENSION) *cert,
                                                 IssuerAlternativeNameExtension &ext);

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_PRIV_HPP
