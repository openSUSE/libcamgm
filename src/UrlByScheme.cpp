/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             core library                             |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       UrlByScheme.cpp

  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   UrlBase.hpp
 * @brief  LiMaL url scheme repository access methods.
 */
#include "Utils.hpp"
#include "UrlByScheme.hpp"
#include "LDAPUrlImpl.hpp"


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

// -------------------------------------------------------------------
namespace
{

	// -----------------------------------------------------------
	struct url_by_scheme
	{
		const char * const scheme;
		UrlRef           (*initfn)();
	};

	// -----------------------------------------------------------
	UrlRef init_url_no_authority()
	{
		UrlRef ref( new UrlBase());

		// disallow authority...
		ref->config("with_authority",   "n");

		// path is mandatory
		ref->config("require_pathname", "m");

		// don't show empty authority
		ref->setViewOptions( ca_mgm::url::ViewOptions() -
		                     ca_mgm::url::ViewOptions::EMPTY_AUTHORITY);

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_file()
	{
		UrlRef ref( new UrlBase());

		// RFC1738, 3.10: allow host, but no port, user, pass
		ref->config("with_authority",   "y");
		ref->config("with_port",        "n");
		ref->config("rx_username",      "");
		ref->config("rx_password",      "");

		// path is mandatory
		ref->config("require_pathname", "m");

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_ftp()
	{
		UrlRef ref( new UrlBase());

		// host is mandatory
		ref->config("require_host",     "m");

		// always encode 2. slash
		ref->config("path_encode_slash2", "y");

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_http()
	{
		UrlRef ref( new UrlBase());

		// host is mandatory
		ref->config("require_host",     "m");

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_ldap()
	{
		UrlRef ref( new LDAPUrlImpl());

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_zypp_media_local()
	{
		UrlRef ref( new UrlBase());

		// disallow authority...
		ref->config("with_authority",   "n");

		// path is mandatory
		ref->config("require_pathname", "m");

		return ref;
	}

	// -----------------------------------------------------------
	UrlRef init_url_zypp_media_remote()
	{
		UrlRef ref( new UrlBase());

		// host is mandatory
		ref->config("require_host",     "m");

		return ref;
	}

	// -----------------------------------------------------------
	static url_by_scheme url_by_scheme_table[] = {

		{ "urn",     init_url_no_authority},
		{ "mailto",  init_url_no_authority},

		{ "dir",     init_url_file},
		{ "file",    init_url_file},

		{ "ldap",    init_url_ldap},
		{ "ldaps",   init_url_ldap},

		{ "ftp",     init_url_ftp},
		{ "http",    init_url_http},
		{ "https",   init_url_http},

		{ "hd",      init_url_zypp_media_local},
		{ "cd",      init_url_zypp_media_local},
		{ "dvd",     init_url_zypp_media_local},
		{ "iso",     init_url_zypp_media_local},

		{ "nfs",     init_url_zypp_media_remote},
		{ "smb",     init_url_zypp_media_remote},
		{ "cifs",    init_url_zypp_media_remote},

		{NULL, NULL}
	};

}	// anonymous namespace


// -------------------------------------------------------------------
ca_mgm::url::UrlRef
getUrlByScheme(const std::string &scheme)
{
	url_by_scheme *ptr;
	for( ptr=url_by_scheme_table; ptr->scheme != NULL; ptr++)
	{
		if( scheme == ptr->scheme && ptr->initfn != NULL)
		{
			return ptr->initfn();
		}
	}
	return ca_mgm::url::UrlRef();
}


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
