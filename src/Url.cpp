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

  File:       UrlBase.cpp

  Maintainer: Marius Tomaschewski

/-*/

#include <ca-mgm/Url.hpp>
#include <ca-mgm/PosixRegEx.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/Exception.hpp>

#include "UrlByScheme.hpp"
#include "Utils.hpp"


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{


// -----------------------------------------------------------------
Url::~Url()
{
}


// -----------------------------------------------------------------
Url::Url()
	: m_impl( new UrlBase())
{
}


// -----------------------------------------------------------------
Url::Url(const Url &url)
	: m_impl( url.m_impl)
{
}


// -----------------------------------------------------------------
Url::Url(const ca_mgm::url::UrlRef &url)
  : m_impl( url)
{
	if( !m_impl)
	{
		CA_MGM_THROW(url::UrlException,
			__("The URL implementation reference cannot be empty.")
		);
	}
}


// -----------------------------------------------------------------
Url::Url(const std::string &urlString)
  : m_impl( parseUrl(urlString))
{
}


// -----------------------------------------------------------------
Url&
Url::operator = (const std::string &urlString)
{
	UrlRef url( parseUrl(urlString));
	if( !url)
	{
		CA_MGM_THROW(url::UrlException,
			__("The URL implementation reference cannot be empty.")
		);
	}
	m_impl = url;
	return *this;
}


// -----------------------------------------------------------------
Url&
Url::operator = (const Url &url)
{
	m_impl = url.m_impl;
	return *this;
}


// -----------------------------------------------------------------
// static
UrlRef
Url::parseUrl(const std::string &urlString)
{
	try
	{
		UrlComponents components( parse_url_string(urlString));

		UrlRef        url(getUrlByScheme( components.scheme));
		if( !url)
		{
			*url = UrlBase();
		}
		url->init(components);

		return url;
	}
	catch(const ca_mgm::Exception &e)
	{
		CA_MGM_THROW_SUBEX(url::UrlParsingException,
			str::form(__("Unable to parse url string '%s'."),
			       urlString.c_str()).c_str(), e
		);
	}
	catch( ... )
	{
		CA_MGM_THROW(url::UrlParsingException,
			str::form(__("Unable to parse url string '%s'."),
			       urlString.c_str()).c_str()
		);
	}
}


// -----------------------------------------------------------------
std::vector<std::string>
Url::getKnownSchemes() const
{
	return m_impl->getKnownSchemes();
}


// -----------------------------------------------------------------
bool
Url::isValidScheme(const std::string &scheme) const
{
	return m_impl->isValidScheme(scheme);
}


// -----------------------------------------------------------------
bool
Url::isValid() const
{
  return m_impl->isValid();
}


// -----------------------------------------------------------------
std::string
Url::toString() const
{
  return m_impl->toString();
}


// -----------------------------------------------------------------
std::string
Url::toCompleteString() const
{
	// make sure, all url components are included;
	// regardless of the current configuration...
	ViewOptions opts(getViewOptions() +
			 ViewOptions::WITH_SCHEME +
			 ViewOptions::WITH_USERNAME +
			 ViewOptions::WITH_PASSWORD +
			 ViewOptions::WITH_HOST +
			 ViewOptions::WITH_PORT +
			 ViewOptions::WITH_PATH_NAME +
			 ViewOptions::WITH_PATH_PARAMS +
			 ViewOptions::WITH_QUERY_STR +
			 ViewOptions::WITH_FRAGMENT);
	return m_impl->toString(opts);
}


// -----------------------------------------------------------------
std::string
Url::toString(const ViewOptions &opts) const
{
	return m_impl->toString(opts);
}


// -----------------------------------------------------------------
std::string
Url::getScheme() const
{
	 return m_impl->getScheme();
}


// -----------------------------------------------------------------
std::string
Url::getAuthority() const
{
  	return m_impl->getAuthority();
}

// -----------------------------------------------------------------
std::string
Url::getPathData() const
{
  	return m_impl->getPathData();
}


// -----------------------------------------------------------------
std::string
Url::getQueryString() const
{
	return m_impl->getQueryString();
}


// -----------------------------------------------------------------
std::string
Url::getFragment(ca_mgm::url::EEncoding eflag) const
{
	return m_impl->getFragment(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getUsername(EEncoding eflag) const
{
	return m_impl->getUsername(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getPassword(EEncoding eflag) const
{
	return m_impl->getPassword(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getHost(EEncoding eflag) const
{
	return m_impl->getHost(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getPort() const
{
	return m_impl->getPort();
}


// -----------------------------------------------------------------
std::string
Url::getPathName(EEncoding eflag) const
{
	return m_impl->getPathName(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getPathParams() const
{
	return m_impl->getPathParams();
}


// -----------------------------------------------------------------
std::vector<std::string>
Url::getPathParamsArray() const
{
	 return m_impl->getPathParamsArray();
}


// -----------------------------------------------------------------
ca_mgm::url::ParamMap
Url::getPathParamsMap(EEncoding eflag) const
{
	return m_impl->getPathParamsMap(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getPathParam(const std::string &param, EEncoding eflag) const
{
	 return m_impl->getPathParam(param, eflag);
}


// -----------------------------------------------------------------
std::vector<std::string>
Url::getQueryStringArray() const
{
	return m_impl->getQueryStringArray();
}


// -----------------------------------------------------------------
ca_mgm::url::ParamMap
Url::getQueryStringMap(EEncoding eflag) const
{
	return m_impl->getQueryStringMap(eflag);
}


// -----------------------------------------------------------------
std::string
Url::getQueryParam(const std::string &param, EEncoding eflag) const
{
	return m_impl->getQueryParam(param, eflag);
}


// -----------------------------------------------------------------
void
Url::setScheme(const std::string &scheme)
{
	if(scheme == m_impl->getScheme())
	{
		return;
	}
	if( m_impl->isKnownScheme(scheme))
	{
		m_impl->setScheme(scheme);
		return;
	}
	UrlRef url = getUrlByScheme(scheme);
	if( !url)
	{
		*url = UrlBase();
	}
	url->setScheme     ( scheme);
	url->setAuthority  ( m_impl->getAuthority());
	url->setPathData   ( m_impl->getPathData());
	url->setQueryString( m_impl->getQueryString());
	url->setFragment   ( m_impl->getFragment(ca_mgm::url::E_ENCODED), ca_mgm::url::E_ENCODED);
	m_impl = url;
}


// -----------------------------------------------------------------
void
Url::setAuthority(const std::string &authority)
{
	m_impl->setAuthority(authority);
}


// -----------------------------------------------------------------
void
Url::setPathData(const std::string &pathdata)
{
	m_impl->setPathData(pathdata);
}


// -----------------------------------------------------------------
void
Url::setQueryString(const std::string &querystr)
{
	m_impl->setQueryString(querystr);
}


// -----------------------------------------------------------------
void
Url::setFragment(const std::string &fragment, EEncoding eflag)
{
	m_impl->setFragment(fragment, eflag);
}


// -----------------------------------------------------------------
void
Url::setUsername(const std::string &user, EEncoding eflag)
{
	m_impl->setUsername(user, eflag);
}


// -----------------------------------------------------------------
void
Url::setPassword(const std::string &pass, EEncoding eflag)
{
	m_impl->setPassword(pass, eflag);
}


// -----------------------------------------------------------------
void
Url::setHost(const std::string &host, EEncoding eflag)
{
	m_impl->setHost(host, eflag);
}


// -----------------------------------------------------------------
void
Url::setPort(const std::string &port)
{
	m_impl->setPort(port);
}


// -----------------------------------------------------------------
void
Url::setPathName(const std::string &path, EEncoding eflag)
{
	m_impl->setPathName(path, eflag);
}


// -----------------------------------------------------------------
void
Url::setPathParams(const std::string &params)
{
	m_impl->setPathParams(params);
}


// -----------------------------------------------------------------
void
Url::setPathParamsArray(const std::vector<std::string> &parray)
{
	m_impl->setPathParamsArray(parray);
}


// -----------------------------------------------------------------
void
Url::setPathParamsMap(const ca_mgm::url::ParamMap &pmap)
{
	m_impl->setPathParamsMap(pmap);
}


// -----------------------------------------------------------------
void
Url::setPathParam(const std::string &param, const std::string &value)
{
	m_impl->setPathParam(param, value);
}


// -----------------------------------------------------------------
void
Url::setQueryStringArray(const std::vector<std::string> &qarray)
{
	m_impl->setQueryStringArray(qarray);
}


// -----------------------------------------------------------------
void
Url::setQueryStringMap(const ca_mgm::url::ParamMap &pmap)
{
	m_impl->setQueryStringMap(pmap);
}

// -----------------------------------------------------------------
void
Url::setQueryParam(const std::string &param, const std::string &value)
{
	m_impl->setQueryParam(param, value);
}

// -----------------------------------------------------------------
ViewOptions
Url::getViewOptions() const
{
	return m_impl->getViewOptions();
}

// -----------------------------------------------------------------
void
Url::setViewOptions(const ViewOptions &vopts)
{
	m_impl->setViewOptions(vopts);
}

// -----------------------------------------------------------------
std::ostream & operator<<(std::ostream &os, const Url &url)
{
	return os << url.toString();
}


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
