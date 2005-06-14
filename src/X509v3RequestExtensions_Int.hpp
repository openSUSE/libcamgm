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

  File:       X509v3RequestExtensions_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_INT_HPP
#define    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3RequestExtensions.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class X509v3RequestExtensions_Int : public X509v3RequestExtensions {
    public:
        X509v3RequestExtensions_Int();
        X509v3RequestExtensions_Int(X509_REQ* req);
        virtual ~X509v3RequestExtensions_Int();

    private:
        X509v3RequestExtensions_Int(const X509v3RequestExtensions_Int& extensions);

        X509v3RequestExtensions_Int& operator=(const X509v3RequestExtensions_Int& extensions);

    };
}
}

#endif // LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_INT_HPP
