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

namespace CA_MGM_NAMESPACE
{

// -------------------------------------------------------------------
#define LOGIT(level,message)	\
LIMAL_SLOG(Logger("ca-mgm"), level, message)

#define LOGIT_DEBUG(message)	\
	LIMAL_SLOG(Logger("ca-mgm"), blocxx::E_DEBUG_LEVEL, message)

#define LOGIT_INFO(message)	\
	LIMAL_SLOG(Logger("ca-mgm"), blocxx::E_INFO_LEVEL, message)

#define LOGIT_ERROR(message)	\
	LIMAL_SLOG(Logger("ca-mgm"), blocxx::E_ERROR_LEVEL, message)

#define LOGIT_DEBUG_STRINGARRAY(text, stringarray)                      \
	Logger d("ca-mgm");                                          \
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
#define __(MSG)  gettext( MSG )


// -------------------------------------------------------------------


// FIXME: what is the format of a hex number?? 0a:0f or 0a0f
//        currently allowed is both
inline ValueCheck initHexCheck() {
	ValueCheck checkHex =
		ValueCheck(new ValuePosixRECheck("^[0-9a-fA-F:]*[0-9a-fA-F]{2}$" ));

	return checkHex;
}

inline ValueCheck initOIDCheck() {
	ValueCheck checkOID =
		ValueCheck(new ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

	return checkOID;
}

inline ValueCheck initURICheck() {
	ValueCheck checkURI =
		ValueCheck(new ValuePosixRECheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\\\?([^#]*))?(#(.*))?"  ));

	return checkURI;
}

inline ValueCheck initEmailCheck() {
	ValueCheck checkEmail =
		ValueCheck(new ValuePosixRECheck("^[^@]+@[^@]+$"));

	return checkEmail;
}

inline ValueCheck initDNSCheck() {
	ValueCheck checkDNS =
		ValueCheck(new ValuePosixRECheck("^[^ ]+$"));

	return checkDNS;
}

inline ValueCheck initIP4Check() {
	ValueCheck checkIP =
		ValueCheck(new ValuePosixRECheck("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"));

	return checkIP;
}

inline ValueCheck initIP6Check() {
	ValueCheck checkIP =
		ValueCheck(new ValuePosixRECheck("^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]){1,4}$"))
		.Or(new ValuePosixRECheck("^:(:[0-9a-fA-F]{1,4}){1,6}$"))
		.Or(new ValuePosixRECheck("^([0-9a-fA-F]{1,4}:){1,6}:$"))
		.Or(
			ValueCheck(
							  ValueCheck( new ValuePosixRECheck( "^(([0-9a-fA-F]{1,4}):){1,6}(:([0-9a-fA-F]{1,4})){1,6}$"))
					    ).And(
							  ValueCheck( new ValuePosixRECheck("^([^:]*:){8,}")).Not()
						).And(
							  ValueCheck( new ValuePosixRECheck("::.*::") ).Not()
							 )
		   );

	return checkIP;
}

inline ValueCheck initAccessOIDCheck() {
	ValueCheck checkAccessOID =
		ValueCheck(new ValuePosixRECheck("^(OCSP|caIssuers)$"))
		.Or(new ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

	return checkAccessOID;
}

inline std::vector<blocxx::String>
	checkLiteralValueList(const std::list<LiteralValue>& list)
{
	std::vector<blocxx::String> result;
	std::list<LiteralValue>::const_iterator it = list.begin();
	for(;it != list.end(); it++) {
		//result.appendArray((*it).verify());
                std::vector<blocxx::String> v = (*it).verify();
                result.insert(result.end(), v.begin(), v.end());
	}
	return result;
}

inline blocxx::String type2Section(Type type, bool v3section)
{
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
		BLOCXX_THROW(ValueException, blocxx::Format("wrong type: %1", type).c_str());
	}
	LOGIT_DEBUG("type2Section: type=" << type << " result=" << result);
	return result;
}

// throws or returns the process exit code or -1 (term by signal).
int wrapExecuteProcessAndGatherOutput(
                                       const std::vector<blocxx::String> &cmd,
                                       blocxx::String                      &out,
                                       blocxx::String                      &err,
                                       const blocxx::EnvVars               &env,
                                       int                                 tmax=-1,
                                       int                                 omax=-1,
                                       const blocxx::String                &in=blocxx::String()
                                     );

inline int rehashCAs(const blocxx::String &repositoryDir)
{
	std::vector<blocxx::String> cmd;
	cmd.push_back(C_REHASH_COMMAND);
	cmd.push_back(repositoryDir);

	blocxx::EnvVars env;
	env.addVar("PATH", "/usr/bin/");

	blocxx::String stdOutput;
	blocxx::String errOutput;
	int    status = -1;
	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
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

std::vector<blocxx::String> convStringArray(const blocxx::StringArray &in);
void appendArray(std::vector<blocxx::String> &in, const std::vector<blocxx::String> &arr);


}
// -------------------------------------------------------------------

#endif // LIMAL_CA_MGM_UTILS_HPP
