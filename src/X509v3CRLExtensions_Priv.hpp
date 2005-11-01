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

    class X509v3CRLExts_Priv : public X509v3CRLExts {
    public:
        X509v3CRLExts_Priv();
        X509v3CRLExts_Priv(STACK_OF(X509_EXTENSION) *extensions);
        X509v3CRLExts_Priv(const X509v3CRLExts_Priv& extensions);
        virtual ~X509v3CRLExts_Priv();

        void     setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExt &ext);
        void     setIssuerAlternativeName(const IssuerAlternativeNameExt &ext);

    private:

        X509v3CRLExts_Priv& operator=(const X509v3CRLExts_Priv& extensions);

        void parseIssuerAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                                 IssuerAlternativeNameExt &ext);

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_PRIV_HPP
