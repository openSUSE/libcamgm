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

#include <limal/Url.hpp>
#include <blocxx/PosixRegEx.hpp>
#include <blocxx/Format.hpp>

#include "UrlByScheme.hpp"
#include "Utils.hpp"


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

using namespace blocxx;


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
		BLOCXX_THROW(url::UrlException,
			__("The URL implementation reference cannot be empty.")
		);
	}
}


// -----------------------------------------------------------------
Url::Url(const blocxx::String &urlString)
  : m_impl( parseUrl(urlString))
{
}


// -----------------------------------------------------------------
Url&
Url::operator = (const blocxx::String &urlString)
{
	UrlRef url( parseUrl(urlString));
	if( !url)
	{
		BLOCXX_THROW(url::UrlException,
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
Url::parseUrl(const blocxx::String &urlString)
{
	try
	{
		UrlComponents components( parse_url_string(urlString));

		UrlRef        url(getUrlByScheme( components.scheme));
		if( !url)
		{
			url = new UrlBase();
		}
		url->init(components);

		return url;
	}
	catch(const blocxx::Exception &e)
	{
		BLOCXX_THROW_SUBEX(url::UrlParsingException,
			Format(__("Unable to parse url string '%1'."),
			       urlString).c_str(), e
		);
	}
	catch( ... )
	{
		BLOCXX_THROW(url::UrlParsingException,
			Format(__("Unable to parse url string '%1'."),
			       urlString).c_str()
		);
	}
}


// -----------------------------------------------------------------
std::vector<blocxx::String>
Url::getKnownSchemes() const
{
	return m_impl->getKnownSchemes();
}


// -----------------------------------------------------------------
bool
Url::isValidScheme(const blocxx::String &scheme) const
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
blocxx::String
Url::toString() const
{
  return m_impl->toString();
}


// -----------------------------------------------------------------
blocxx::String
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
blocxx::String
Url::toString(const ViewOptions &opts) const
{
	return m_impl->toString(opts);
}


// -----------------------------------------------------------------
blocxx::String
Url::getScheme() const
{
	 return m_impl->getScheme();
}


// -----------------------------------------------------------------
blocxx::String
Url::getAuthority() const
{
  	return m_impl->getAuthority();
}

// -----------------------------------------------------------------
blocxx::String
Url::getPathData() const
{
  	return m_impl->getPathData();
}


// -----------------------------------------------------------------
blocxx::String
Url::getQueryString() const
{
	return m_impl->getQueryString();
}


// -----------------------------------------------------------------
blocxx::String
Url::getFragment(ca_mgm::url::EEncoding eflag) const
{
	return m_impl->getFragment(eflag);
}


// -----------------------------------------------------------------
blocxx::String
Url::getUsername(EEncoding eflag) const
{
	return m_impl->getUsername(eflag);
}


// -----------------------------------------------------------------
blocxx::String
Url::getPassword(EEncoding eflag) const
{
	return m_impl->getPassword(eflag);
}


// -----------------------------------------------------------------
blocxx::String
Url::getHost(EEncoding eflag) const
{
	return m_impl->getHost(eflag);
}


// -----------------------------------------------------------------
blocxx::String
Url::getPort() const
{
	return m_impl->getPort();
}


// -----------------------------------------------------------------
blocxx::String
Url::getPathName(EEncoding eflag) const
{
	return m_impl->getPathName(eflag);
}


// -----------------------------------------------------------------
blocxx::String
Url::getPathParams() const
{
	return m_impl->getPathParams();
}


// -----------------------------------------------------------------
std::vector<blocxx::String>
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
blocxx::String
Url::getPathParam(const blocxx::String &param, EEncoding eflag) const
{
	 return m_impl->getPathParam(param, eflag);
}


// -----------------------------------------------------------------
std::vector<blocxx::String>
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
blocxx::String
Url::getQueryParam(const blocxx::String &param, EEncoding eflag) const
{
	return m_impl->getQueryParam(param, eflag);
}


// -----------------------------------------------------------------
void
Url::setScheme(const blocxx::String &scheme)
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
		url = new UrlBase();
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
Url::setAuthority(const blocxx::String &authority)
{
	m_impl->setAuthority(authority);
}


// -----------------------------------------------------------------
void
Url::setPathData(const blocxx::String &pathdata)
{
	m_impl->setPathData(pathdata);
}


// -----------------------------------------------------------------
void
Url::setQueryString(const blocxx::String &querystr)
{
	m_impl->setQueryString(querystr);
}


// -----------------------------------------------------------------
void
Url::setFragment(const blocxx::String &fragment, EEncoding eflag)
{
	m_impl->setFragment(fragment, eflag);
}


// -----------------------------------------------------------------
void
Url::setUsername(const blocxx::String &user, EEncoding eflag)
{
	m_impl->setUsername(user, eflag);
}


// -----------------------------------------------------------------
void
Url::setPassword(const blocxx::String &pass, EEncoding eflag)
{
	m_impl->setPassword(pass, eflag);
}


// -----------------------------------------------------------------
void
Url::setHost(const blocxx::String &host, EEncoding eflag)
{
	m_impl->setHost(host, eflag);
}


// -----------------------------------------------------------------
void
Url::setPort(const blocxx::String &port)
{
	m_impl->setPort(port);
}


// -----------------------------------------------------------------
void
Url::setPathName(const blocxx::String &path, EEncoding eflag)
{
	m_impl->setPathName(path, eflag);
}


// -----------------------------------------------------------------
void
Url::setPathParams(const blocxx::String &params)
{
	m_impl->setPathParams(params);
}


// -----------------------------------------------------------------
void
Url::setPathParamsArray(const std::vector<blocxx::String> &parray)
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
Url::setPathParam(const blocxx::String &param, const blocxx::String &value)
{
	m_impl->setPathParam(param, value);
}


// -----------------------------------------------------------------
void
Url::setQueryStringArray(const std::vector<blocxx::String> &qarray)
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
Url::setQueryParam(const blocxx::String &param, const blocxx::String &value)
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
