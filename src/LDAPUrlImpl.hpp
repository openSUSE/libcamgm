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

  File:       LDAPUrlImpl.hpp

  Maintainer: Marius Tomaschewski

/-*/
#ifndef  LIMAL_LDAPURLIMPL_HPP
#define  LIMAL_LDAPURLIMPL_HPP
#include <limal/UrlBase.hpp>


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

using namespace blocxx;


// ---------------------------------------------------------------
class LDAPUrlImpl: public UrlBase
{
public:
	LDAPUrlImpl();
	LDAPUrlImpl(const LDAPUrlImpl &url);

	virtual UrlBase *
	clone() const;

	virtual std::vector<std::string>
	getKnownSchemes() const;

	virtual void
	configure();

	virtual ca_mgm::url::ParamMap
	getQueryStringMap(ca_mgm::url::EEncoding eflag) const;

	virtual void
	setQueryStringMap(const ca_mgm::url::ParamMap &pmap);
};


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of LIMAL_NAMESPACE
#endif // LIMAL_LDAPURLIMPL_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
