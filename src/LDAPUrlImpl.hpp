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
#ifndef  CA_MGM_LDAPURLIMPL_HPP
#define  CA_MGM_LDAPURLIMPL_HPP
#include <ca-mgm/UrlBase.hpp>


// -------------------------------------------------------------------
namespace CA_MGM_NAMESPACE
{
namespace url
{

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
}      // End of CA_MGM_NAMESPACE
#endif // CA_MGM_LDAPURLIMPL_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
