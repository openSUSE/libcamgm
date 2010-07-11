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
#include <limal/ca-mgm/config.h>

#include "Utils.hpp"
#include <libintl.h>
#include <openssl/objects.h>
#include <pthread.h>

// -------------------------------------------------------------------
namespace CA_MGM_NAMESPACE
{
namespace
{
	// -----------------------------------------------------------
pthread_once_t g_i18n_init_guard = PTHREAD_ONCE_INIT;


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
	pthread_once(&g_i18n_init_guard, init_i18n_domain);
	return ::dgettext(i18n_domain, msgid);
}


// -------------------------------------------------------------------
const char *       gettext (const char *msgid,
                            const char *plural,
                            unsigned long int n)
{
	pthread_once(&g_i18n_init_guard, init_i18n_domain);
	return ::dngettext(i18n_domain, msgid, plural, n);
}


// -------------------------------------------------------------------
int wrapExecuteProcessAndGatherOutput(
                                       const std::vector<std::string> &cmd,
                                       std::string                    &out,
                                       std::string                    &err,
                                       const blocxx::EnvVars          &env,
                                       int                            tmax,
                                       int                            omax,
                                       const std::string              &in
                                     )
{
	int exitStatus = -1;

	blocxx::Process::Status status;

	status = blocxx::Exec::executeProcessAndGatherOutput(
		blocxx::StringArray(cmd.begin(), cmd.end()),
        out, err, env,
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
	return exitStatus;
}

/* FIXME: remove
std::vector<std::string>
convStringArray(const std::stringArray &in)
{
  std::vector<std::string> out(in.begin(), in.end());
  return out;
}
*/

void
appendArray(std::vector<std::string> &in, const std::vector<std::string> &arr)
{
  in.insert(in.end(), arr.begin(), arr.end());
}

// -------------------------------------------------------------------
}       // End of CA_MGM_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
