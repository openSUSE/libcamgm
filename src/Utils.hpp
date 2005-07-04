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
#include <limal/ValueRegExCheck.hpp>


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


// -------------------------------------------------------------------

#endif // LIMAL_CA_MGM_UTILS_HPP
