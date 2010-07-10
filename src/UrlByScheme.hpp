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
#ifndef   LIMAL_URLBYSCHEME_HPP
#define   LIMAL_URLBYSCHEME_HPP

#include <limal/UrlBase.hpp>


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
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
}      // End of LIMAL_NAMESPACE
#endif // LIMAL_URLBYSCHEME_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
