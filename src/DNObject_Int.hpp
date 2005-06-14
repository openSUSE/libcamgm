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

  File:       DNObject_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_INT_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class DNObject_Int : public DNObject {
    public:
        DNObject_Int(X509* cert);    
        virtual ~DNObject_Int();

    private:
        DNObject_Int(const DNObject_Int& obj);    

        DNObject_Int& operator=(const DNObject_Int& obj);
    };

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_INT_HPP
