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
#include  <errno.h>

#define   REPOSITORY   "/var/lib/CAM/"

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
	
	enum EErrorCodes
	{
		E_GENERIC  = blocxx::Exception::UNKNOWN_ERROR_CODE,  // == -1
		E_C_EMPTY  = -100, // value empty
		E_ST_EMPTY = -101,
		E_L_EMPTY  = -102,
		E_O_EMPTY  = -103,
		E_OU_EMPTY = -104,
		E_CN_EMPTY = -105,
		E_EM_EMPTY = -106,
		E_C_NF     = -110, // value not found
		E_ST_NF    = -111,
		E_L_NF     = -112,
		E_O_NF     = -113,
		E_OU_NF    = -114,
		E_CN_NF    = -115,
		E_EM_NF    = -116,
		E_C_NM     = -120, // (no match) value does not match CA
		E_ST_NM    = -121,
		E_L_NM     = -122,
		E_O_NM     = -123,
		E_OU_NM    = -124,
		E_CN_NM    = -125,
		E_EM_NM    = -126,
		E_INVALID_PASSWD = -200,   // invalid password
		E_FILE_NOT_FOUND = ENOENT, //errno
		E_FILE_EXISTS    = EEXIST  //errno
	};
}

#endif   // LIMAL_CA_MGM_COMMON_DATA_HPP
