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

// -------------------------------------------------------------------

#endif // LIMAL_CA_MGM_UTILS_HPP
