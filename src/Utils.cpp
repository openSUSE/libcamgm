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
#include <blocxx/ThreadOnce.hpp>

#include "Utils.hpp"
#include <libintl.h>
#include <openssl/objects.h>

// -------------------------------------------------------------------
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
                                       const std::vector<blocxx::String> &cmd,
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

std::vector<blocxx::String>
convStringArray(const blocxx::StringArray &in)
{
  std::vector<blocxx::String> out(in.begin(), in.end());
  return out;
}

void
appendArray(std::vector<blocxx::String> &in, const std::vector<blocxx::String> &arr)
{
  in.insert(in.end(), arr.begin(), arr.end());
}

// -------------------------------------------------------------------
}       // End of CA_MGM_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
