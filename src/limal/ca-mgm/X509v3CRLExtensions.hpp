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
#ifndef    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Collection of X509v3 extension for presenting CRLs
     *
     * This class includes a collection of X509v3 extension for presenting CRLs
     * (Read-only data representation)
     */
    class X509v3CRLExtensions {
    public:
        X509v3CRLExtensions(const X509v3CRLExtensions& extensions);
        virtual ~X509v3CRLExtensions();

        X509v3CRLExtensions& operator=(const X509v3CRLExtensions& extensions);

        AuthorityKeyIdentifierExtension getAuthorityKeyIdentifier() const;
        IssuerAlternativeNameExtension  getIssuerAlternativeName() const;

    protected:
        X509v3CRLExtensions();

        AuthorityKeyIdentifierExtension authorityKeyIdentifier;
        IssuerAlternativeNameExtension  issuerAlternativeName;

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CRL_EXTENSIONS_HPP
