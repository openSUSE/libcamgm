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

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    typedef blocxx::String                             String;
    typedef blocxx::List<String>                       StringList;
    typedef blocxx::List<blocxx::Map<String, String> > StringMapList;

    typedef blocxx::Array<blocxx::Int8>                ByteArray; 

    enum Type {
        Client_Req,
        Server_Req,
        CA_Req,
        Client_Cert,
        Server_Cert,
        CA_Cert,
        CRL
    };


    /* obsolete */
    enum CertType {
        CertType_Client,
        CertType_Server,
        CertType_CA
    };

    enum FormatType {
        PEM,
        DER
    };

    enum CertificatePurpose {
        sslclient,
        sslserver,
        nssslserver,
        smimesign,
        smimeencrypt,
        crlsign,
        any,
        ocsphelper
    };

    enum KeyAlg {
        RSA,
        DSA,
        DH
    };

    enum SigAlg {
        SHA1RSA,
        MD5RSA,
        SHA1DSA,
    };

    enum MD {
        SHA1,
        MD5,
        MDC2,
    };

}
}

#endif   // LIMAL_CA_MGM_COMMON_DATA_HPP
