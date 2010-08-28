/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                          |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       config.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

/-*/
#include  <ca-mgm/config.h>

extern "C" {


// -------------------------------------------------------------------
	const char * ca_mgm_lib_version()
	{
		return CA_MGM_LIB_VERSION;
	}


// -------------------------------------------------------------------
	unsigned int ca_mgm_api_version()
	{
		return CA_MGM_API_VERSION;
	}


} /* extern C */

/* vim: set ts=8 sts=8 sw=8 ai noet: */

