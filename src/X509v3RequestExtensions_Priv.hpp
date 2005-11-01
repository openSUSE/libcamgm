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

  File:       X509v3RequestExtensions_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_PRIV_HPP
#define    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3RequestExtensions.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class X509v3RequestExts_Priv : public X509v3RequestExts {
    public:
        X509v3RequestExts_Priv();
        X509v3RequestExts_Priv(STACK_OF(X509_EXTENSION)* extensions);
        X509v3RequestExts_Priv(const X509v3RequestExts_Priv& extensions);
        virtual ~X509v3RequestExts_Priv();

    private:

        X509v3RequestExts_Priv&
        operator=(const X509v3RequestExts_Priv& extensions);

        void
        parseStringExt(STACK_OF(X509_EXTENSION)* cert,
                       int nid, StringExtension &ext);

        void
        parseBitExt(STACK_OF(X509_EXTENSION)* cert,
                    int nid, BitExtension &ext);
        
        void
        parseExtendedKeyUsageExt(STACK_OF(X509_EXTENSION)* cert,
                                 ExtendedKeyUsageExt &ext);
        
        void
        parseBasicConstraintsExt(STACK_OF(X509_EXTENSION)* cert,
                                 BasicConstraintsExt &ext);
        
        void
        parseSubjectKeyIdentifierExt(STACK_OF(X509_EXTENSION) *cert,
                                     SubjectKeyIdentifierExt &ext);

        void
        parseSubjectAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                       SubjectAlternativeNameExt &ext);

    };
}
}

#endif // LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_PRIV_HPP
