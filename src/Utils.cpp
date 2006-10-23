/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                          limal core library                          |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       Utils.cpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   Utils.cpp
 * @brief  This file is private for the limal core library.
 *         It implements common utilities, like the gettext
 *         text domain initializaton.
 */
#include <limal/config.h>
#include <blocxx/ThreadOnce.hpp>

#include "Utils.hpp"
#include <libintl.h>
#include <openssl/objects.h>

// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{
namespace
{
	// -----------------------------------------------------------
	blocxx::OnceFlag   g_i18n_init_guard = BLOCXX_ONCE_INIT;


	// -----------------------------------------------------------
	void               init_i18n_domain()
	{
		bindtextdomain( i18n_domain, LOCALEDIR);
		bind_textdomain_codeset( i18n_domain, "utf8");
	}
}


// -------------------------------------------------------------------
const char *       gettext (const char *msgid)
{
	blocxx::callOnce( g_i18n_init_guard, init_i18n_domain);
	return ::dgettext(i18n_domain, msgid);
}


// -------------------------------------------------------------------
const char *       gettext (const char *msgid,
                            const char *plural,
                            unsigned long int n)
{
	blocxx::callOnce( g_i18n_init_guard, init_i18n_domain);
	return ::dngettext(i18n_domain, msgid, plural, n);
}


// -------------------------------------------------------------------
int wrapExecuteProcessAndGatherOutput(
	const blocxx::Array<blocxx::String> &cmd,
	blocxx::String                      &out,
	blocxx::String                      &err,
	const blocxx::EnvVars               &env,
	int                                 tmax,
	int                                 omax,
	const blocxx::String                &in
)
{
	int exitStatus = -1;

#if BLOCXX_LIBRARY_VERSION >= 5
	blocxx::Process::Status status;

	status = blocxx::Exec::executeProcessAndGatherOutput(
		cmd, out, err, env,
		( tmax < 0 ? blocxx::Timeout::infinite :
		  blocxx::Timeout::relative(float(tmax))
		),
		omax, in
	);

	if( status.exitTerminated())
	{
		exitStatus = status.exitStatus();
	}
	else
	if( status.signalTerminated())
	{
		LOGIT_ERROR("Command '" << cmd[0]
		            << "' terminated by signal: "
		            << status.termSignal());
	}
	else
	{
		LOGIT_ERROR("Command '" << cmd[0]
		            << "' execution in unknown state");
	}
#else
	int status = -1;

	blocxx::Exec::executeProcessAndGatherOutput(
		cmd, out, err, status, env,
		( tmax < 0 ?  blocxx::Exec::INFINITE_TIMEOUT : tmax
		),
		omax, in
	);

	if( status != -1)
	{
		if(WIFEXITED(status))
		{
			exitStatus = WEXITSTATUS(status);
		}
		else
		if(WIFSIGNALED(status))
		{
			LOGIT_ERROR("Command '" << cmd[0]
		        	    << "' terminated by signal: "
			            << WTERMSIG(status));
		}
		else
		{
			LOGIT_ERROR("Command '" << cmd[0]
		        	    << "' execution status: "
				    << status);
		}
	}
	else
	{
		LOGIT_ERROR("Command '" << cmd[0]
		            << "' execution failure: "
			    << status);
	}
#endif

	return exitStatus;
}

LiteralValue
gn2lv(GENERAL_NAME *gen)
{
	char oline[256];
	char *s = NULL;
	unsigned char *p = NULL;
	LiteralValue lv;
	
	switch (gen->type)
	{        
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
		case GEN_OTHERNAME:
			// krb5PrincipalName || Microsoft Universal Principal Name 
			if(OBJ_obj2nid(gen->d.otherName->type_id) == NID_ms_upn)
			{				
				lv.setLiteral("othername",
				              (char*)ASN1_STRING_data(gen->d.otherName->value->value.sequence));
			}
			else
			{
				lv.setLiteral("othername",
				              String("unsupported(") + String(OBJ_obj2nid(gen->d.otherName->type_id)) + ")");
			}
			break;
		case GEN_X400:
			lv.setLiteral("X400Name", "unsupported");
			break;
		case GEN_EDIPARTY:
			lv.setLiteral("EdiPartyName", "unsupported");
			break;			
	}
	return lv;
}


// -------------------------------------------------------------------
}       // End of CA_MGM_NAMESPACE
}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
