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
#ifndef   CA_MGM_URLBYSCHEME_HPP
#define   CA_MGM_URLBYSCHEME_HPP

#include <ca-mgm/UrlBase.hpp>


// -------------------------------------------------------------------
namespace CA_MGM_NAMESPACE
{
namespace url
{

// -------------------------------------------------------------------
ca_mgm::url::UrlRef
getUrlByScheme(const std::string &scheme);


// -------------------------------------------------------------------
#if 0
std::vector<std::string>
getUrlBySchemeNames();
#endif


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of CA_MGM_NAMESPACE
#endif // CA_MGM_URLBYSCHEME_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
