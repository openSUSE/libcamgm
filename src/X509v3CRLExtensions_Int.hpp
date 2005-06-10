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

  File:       X509v3CRLExtensions_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_INT_HPP
#define    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CRLExtensions.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class X509v3CRLExtensions_Int : public X509v3CRLExtensions {
    public:
        X509v3CRLExtensions_Int();
        X509v3CRLExtensions_Int(X509_CRL* crl);
        virtual ~X509v3CRLExtensions_Int();

        void     setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext);
        void     setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext);

    private:
        X509v3CRLExtensions_Int(const X509v3CRLExtensions_Int& extensions);

        X509v3CRLExtensions_Int& operator=(const X509v3CRLExtensions_Int& extensions);

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_INT_HPP
