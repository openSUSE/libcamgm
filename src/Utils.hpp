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

#include <blocxx/String.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/Exec.hpp>
#include <blocxx/EnvVars.hpp>

#include <openssl/x509v3.h>

#include "Commands.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{
    
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
                       "(" << (i+1) << "/" << s << "):"                 \
                       << stringarray[i]);                              \
        }                                                               \
    } 

// -------------------------------------------------------------------

	/**
	 * @{
	 * Internationalization gettext-wrapper functions.
	 * This functions initialize the text domain 'i18n_domain'
	 * once and finally forward the calls to the d*gettext
	 * functions using 'i18n_domain' as text domain.
	 *
	 * @param msgid  The singular message to be translated.
	 * @param plural The plural message to be translated.
	 * @param n      The number of the plural message.
	 * @return The translated message or msgid.
	 */
	const char *       gettext (const char *msgid);
	const char *       gettext (const char *msgid,
	                            const char *plural,
	                            unsigned long int n);
	/* @} */

// -------------------------------------------------------------------
/**
 * Text domain for the ca-mgm library.
 */
#define i18n_domain     "limal-ca-mgm"


// -------------------------------------------------------------------
/**
 * Internationalization helper macro.
 */
#define __(MSG)  limal::ca_mgm::gettext( MSG )


// -------------------------------------------------------------------

	
// FIXME: what is the format of a hex number?? 0a:0f or 0a0f
//        currently allowed is both
inline limal::ValueCheck initHexCheck() {
    limal::ValueCheck checkHex =
        limal::ValueCheck(new limal::ValuePosixRECheck("^[0-9a-fA-F:]*[0-9a-fA-F]{2}$" ));
    
    return checkHex;
}

inline limal::ValueCheck initOIDCheck() {
    limal::ValueCheck checkOID =
        limal::ValueCheck(new limal::ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

    return checkOID;
}

inline limal::ValueCheck initURICheck() {
    limal::ValueCheck checkURI =
        limal::ValueCheck(new limal::ValuePosixRECheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\\\?([^#]*))?(#(.*))?"  ));

    return checkURI;
}

inline limal::ValueCheck initEmailCheck() {
    limal::ValueCheck checkEmail =
        limal::ValueCheck(new limal::ValuePosixRECheck("^[^@]+@[^@]+$"));

    return checkEmail;
}

inline limal::ValueCheck initDNSCheck() {
    limal::ValueCheck checkDNS =
        limal::ValueCheck(new limal::ValuePosixRECheck("^[a-z]+[a-z0-9.-]*$"));

    return checkDNS;
}

inline limal::ValueCheck initIPCheck() {
    limal::ValueCheck checkIP =
        limal::ValueCheck(new limal::ValuePosixRECheck("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"));

    return checkIP;
}

inline limal::ValueCheck initAccessOIDCheck() {
    limal::ValueCheck checkAccessOID =
        limal::ValueCheck(new limal::ValuePosixRECheck("^(OCSP|caIssuers)$"))
        .Or(new limal::ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

    return checkAccessOID;
}

inline blocxx::StringArray 
checkLiteralValueList(const blocxx::List<LiteralValue>& list) 
{
    blocxx::StringArray result;
    blocxx::List<limal::ca_mgm::LiteralValue>::const_iterator it = list.begin();
    for(;it != list.end(); it++) {
        result.appendArray((*it).verify());
    }
    return result;
}

inline blocxx::String type2Section(Type type, bool v3section) {
    blocxx::String result;

    switch(type)
    {
        case E_CA_Req:
            if(!v3section)
                result = "req_ca";
            else
                result = "v3_req_ca";
            break;
        case E_Client_Req:
            if(!v3section)
                result = "req_client";
            else
                result = "v3_req_client";
            break;
        case E_Server_Req:
            if(!v3section)
                result = "req_server";
            else
                result = "v3_req_server";
            break;
        case E_CA_Cert:
            if(!v3section)
                result = "ca";
            else
                result = "v3_ca";
            break;
        case E_Client_Cert:
            if(!v3section)
                result = "client_cert";
            else
                result = "v3_client";
            break;
        case E_Server_Cert:
            if(!v3section)
                result = "server_cert";
            else
                result = "v3_server";
            break;
        case E_CRL:
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

// throws or returns the process exit code or -1 (term by signal).
int wrapExecuteProcessAndGatherOutput(
	const blocxx::Array<blocxx::String> &cmd,
	blocxx::String                      &out,
	blocxx::String                      &err,
	const blocxx::EnvVars               &env,
	int                                 tmax=-1,
	int                                 omax=-1,
	const blocxx::String                &in=blocxx::String()
);

inline int rehashCAs(const blocxx::String &repositoryDir) 
{
	blocxx::Array<blocxx::String> cmd;
	cmd.push_back(limal::ca_mgm::C_REHASH_COMMAND);
	cmd.push_back(repositoryDir);
	
	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");
	
	blocxx::String stdOutput;
	blocxx::String errOutput;
	int    status = -1;
	try
	{		
		status = wrapExecuteProcessAndGatherOutput(
			cmd, stdOutput, errOutput, env
		);
    	}
	catch(blocxx::Exception& e)
	{
		LOGIT_INFO( "c_rehash exception:" << e);
	}
    	if(status != 0)
    	{
    		LOGIT_INFO( "c_rehash status:" << blocxx::String(status));
    	}
    	if(!errOutput.empty())
    	{
    		LOGIT_INFO("c_rehash stderr:" << errOutput);
    	}
    	if(!stdOutput.empty())
    	{
    		// this output here is not so important and makes trouble
    		// in testcases
    		//
    		//LOGIT_DEBUG("c_rehash stdout:" << stdOutput);
    	}
    	return status;
}

inline LiteralValue gn2lv(GENERAL_NAME *gen)
{
    char oline[256];
    char *s = NULL;
    unsigned char *p = NULL;
    LiteralValue lv;
    
    switch (gen->type) {
        
        case GEN_EMAIL:
            s = new char[gen->d.ia5->length +1];
            memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
            s[gen->d.ia5->length] = '\0';
            lv.setLiteral("email", s);
            delete [] s;
            break;
            
        case GEN_DNS:
            s = new char[gen->d.ia5->length +1];
            memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
            s[gen->d.ia5->length] = '\0';
            lv.setLiteral("DNS", s);
            delete [] s;
            break;
            
        case GEN_URI:
            s = new char[gen->d.ia5->length +1];
            memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
            s[gen->d.ia5->length] = '\0';
            lv.setLiteral("URI", s);
            delete [] s;
            break;
            
        case GEN_DIRNAME:
            X509_NAME_oneline(gen->d.dirn, oline, 256);
            lv.setLiteral("DirName", oline);
            break;
            
        case GEN_IPADD:
            p = gen->d.ip->data;
            /* BUG: doesn't support IPV6 */
            if(gen->d.ip->length != 4) {
                LOGIT_ERROR("Invalid IP Address: maybe IPv6");
                BLOCXX_THROW(limal::SyntaxException, "Invalid IP Address: maybe IPv6");
                break;
            }
            BIO_snprintf(oline, sizeof oline,
                         "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
            lv.setLiteral("IP", oline);
            break;
            
        case GEN_RID:
            i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
            lv.setLiteral("RID", oline);
            break;
    }
    return lv;
}

}
}
// -------------------------------------------------------------------

#endif // LIMAL_CA_MGM_UTILS_HPP
