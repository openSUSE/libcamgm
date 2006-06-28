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
}       // End of CA_MGM_NAMESPACE
}       // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
