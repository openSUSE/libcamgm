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

  File:       CommonData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_COMMON_DATA_HPP
#define    LIMAL_CA_MGM_COMMON_DATA_HPP

#include  <blocxx/Types.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/List.hpp>
#include  <blocxx/Array.hpp>
#include  <blocxx/Map.hpp>

#define   REPOSITORY   "/var/lib/CAM/"

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    typedef blocxx::String       String;
    typedef blocxx::List<String> StringList;
    
    enum Type {
        E_Client_Req,  //! Client Request
        E_Server_Req,  //! Server Request
        E_CA_Req,      //! CA Request
        E_Client_Cert, //! Client Certificate
        E_Server_Cert, //! Server Certificate
        E_CA_Cert,     //! CA Certificate
        E_CRL          //! Certificate Revocation List
    };

    enum FormatType {
        E_PEM,
        E_DER
    };

    enum KeyAlg {
        E_RSA,
        E_DSA,
        E_DH
    };

    enum SigAlg {
        E_SHA1RSA,
        E_MD5RSA,
        E_SHA1DSA,
    };

    enum MD {
        E_SHA1,
        E_MD5,
        E_MDC2,
    };

}
}

#endif   // LIMAL_CA_MGM_COMMON_DATA_HPP
