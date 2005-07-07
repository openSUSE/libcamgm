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

  File:       Utils.hpp

  Author:     Marius Tomaschewski
              Michael Calmer
  Maintainer: Michael Calmer
/-*/
/**
 * @file   Utils.hpp
 * @brief  This file is private for the ca-mgm library.
 *         It defines common utilities e.g. a helper macro
 *         for logging
 */
#ifndef   LIMAL_CA_MGM_UTILS_HPP
#define   LIMAL_CA_MGM_UTILS_HPP

#include <limal/Logger.hpp>
#include <limal/Exception.hpp>
#include <limal/ValueRegExCheck.hpp>
#include <limal/ca-mgm/LiteralValues.hpp>
#include <limal/ca-mgm/CommonData.hpp>

#include <blocxx/Format.hpp>

// -------------------------------------------------------------------
#define LOGIT(level,message)	\
	LIMAL_SLOG(limal::Logger("ca-mgm"), level, message)

#define LOGIT_DEBUG(message)	\
	LIMAL_SLOG(limal::Logger("ca-mgm"), blocxx::E_DEBUG_LEVEL, message)

#define LOGIT_INFO(message)	\
	LIMAL_SLOG(limal::Logger("ca-mgm"), blocxx::E_INFO_LEVEL, message)

#define LOGIT_ERROR(message)	\
	LIMAL_SLOG(limal::Logger("ca-mgm"), blocxx::E_ERROR_LEVEL, message)

#define LOGIT_DEBUG_STRINGARRAY(text, stringarray)                      \
    limal::Logger d("ca-mgm");                                          \
    if(d.isEnabledFor("DEBUG")) {                                       \
        uint s = stringarray.size();                                    \
        for(uint i = 0; i < s; i++) {                                   \
            LIMAL_SLOG(d, blocxx::E_DEBUG_LEVEL,                        \
                       text <<                                          \
                       "(" << i << "/" << s << "):"                     \
                       << stringarray[i]);                              \
        }                                                               \
    } 


inline static limal::ValueCheck initHexCheck() {
    limal::ValueCheck checkHex =
        limal::ValueCheck(new limal::ValuePosixRECheck("^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$" ));
    
    return checkHex;
}

inline static limal::ValueCheck initOIDCheck() {
    limal::ValueCheck checkOID =
        limal::ValueCheck(new limal::ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

    return checkOID;
}

inline static limal::ValueCheck initURICheck() {
    limal::ValueCheck checkURI =
        limal::ValueCheck(new limal::ValuePosixRECheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\\\?([^#]*))?(#(.*))?"  ));

    return checkURI;
}

inline static limal::ValueCheck initEmailCheck() {
    limal::ValueCheck checkEmail =
        limal::ValueCheck(new limal::ValuePosixRECheck("^[^@]+@[^@]+$"));

    return checkEmail;
}

inline static limal::ValueCheck initDNSCheck() {
    limal::ValueCheck checkDNS =
        limal::ValueCheck(new limal::ValuePosixRECheck("^[a-z]+[a-z0-9.-]*$"));

    return checkDNS;
}

inline static limal::ValueCheck initIPCheck() {
    limal::ValueCheck checkIP =
        limal::ValueCheck(new limal::ValuePosixRECheck("^([0-9]{1,3}\\.){3}[0-9]+$"));

    return checkIP;
}

inline static limal::ValueCheck initAccessOIDCheck() {
    limal::ValueCheck checkAccessOID =
        limal::ValueCheck(new limal::ValuePosixRECheck("^(OCSP|caIssuers)$"))
        .Or(new limal::ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

    return checkAccessOID;
}

inline static blocxx::StringArray 
checkLiteralValueList(const blocxx::List<limal::ca_mgm::LiteralValue>& list) 
{
    blocxx::StringArray result;
    blocxx::List<limal::ca_mgm::LiteralValue>::const_iterator it = list.begin();
    for(;it != list.end(); it++) {
        result.appendArray((*it).verify());
    }
    return result;
}

inline static blocxx::String type2Section(limal::ca_mgm::Type type, bool v3section) {
    blocxx::String result;

    switch(type) {
    case limal::ca_mgm::CA_Req:
        if(!v3section)
            result = "req";
        else
            result = "v3_req_ca";
        break;
    case limal::ca_mgm::Client_Req:
        if(!v3section)
            result = "req_client";
        else
            result = "v3_req_client";
        break;
    case limal::ca_mgm::Server_Req:
        if(!v3section)
                result = "req_server";
        else
            result = "v3_req_server";
        break;
    case limal::ca_mgm::CA_Cert:
        if(!v3section)
            result = "ca";
        else
            result = "v3_ca";
        break;
    case limal::ca_mgm::Client_Cert:
        if(!v3section)
            result = "client_cert";
        else
            result = "v3_client";
        break;
    case limal::ca_mgm::Server_Cert:
        if(!v3section)
            result = "server_cert";
        else
            result = "v3_server";
        break;
    case limal::ca_mgm::CRL:
        if(!v3section)
            result = "ca";
        else
            result = "v3_crl";
        break;
    default:
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, blocxx::Format("wrong type: %1", type).c_str());
    }
    LOGIT_DEBUG("type2Section: type=" << type << " result=" << result);
    return result;
}


// -------------------------------------------------------------------

#endif // LIMAL_CA_MGM_UTILS_HPP
