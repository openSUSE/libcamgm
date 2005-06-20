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

  File:       DNObject_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class DNObject_Priv : public DNObject {
    public:
        DNObject_Priv(X509* cert);    
        virtual ~DNObject_Priv();

    private:
        DNObject_Priv(const DNObject_Priv& obj);    

        DNObject_Priv& operator=(const DNObject_Priv& obj);
    };

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP
