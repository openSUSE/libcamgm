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

#include <limal/UrlBase.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/PosixRegEx.hpp>

#include "Utils.hpp"

#include <climits>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


// -------------------------------------------------------------------
/*
** Default sets of safe characters in url components:
*/
#define SAFE_CHARS_USERNAME   "~!$&'()*+=,;"
#define SAFE_CHARS_PASSWORD   "~!$&'()*+=,;:"
#define SAFE_CHARS_HOSTNAME   "[:]"
#define SAFE_CHARS_PATHNAME   "~!$&'()*+=,:@/"
#define SAFE_CHARS_PATHPARAMS "~!$&'()*+=,:;@/"
#define SAFE_CHARS_QUERYSTR   "~!$&'()*+=,:;@/?"
#define SAFE_CHARS_FRAGMENT   "~!$&'()*+=,:;@/?"


/*
** Default path and query parameter separators:
*/
#define DFLT_PATHPARAMS_SEP  ";"
#define DFLT_PATHPARAM_PSEP  ","
#define DFLT_PATHPARAM_VSEP  "="
#define DFLT_QUERYPARAM_PSEP "&"
#define DFLT_QUERYPARAM_VSEP "="

/*
** Default regex check for valid characters in url components:
*/
#define RX_VALID_SCHEME      "^[a-zA-Z][a-zA-Z0-9\\.+-]*$"
#define RX_VALID_USERNAME    "^([a-zA-Z0-9!$&'\\(\\)*+=,;~\\._-]|%[a-fA-F0-9]{2})+$"
#define RX_VALID_PASSWORD    "^([a-zA-Z0-9!$&'\\(\\)*+=,:;~\\._-]|%[a-fA-F0-9]{2})+$"
#define RX_VALID_HOSTNAME    "^[[:alnum:]]+([\\.-][[:alnum:]]+)*$"
#define RX_VALID_HOSTIPV4    "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$"
#define RX_VALID_HOSTIPV6    "^\\[[:a-fA-F0-9]+(:[0-9]{1,3}(\\.[0-9]{1,3}){3})?\\]$"
#define RX_VALID_PORTNUMBER  "^[0-9]{1,5}$"
#define RX_VALID_PATHNAME    "^([a-zA-Z0-9!$&'\\(\\)*+=,:@/~\\._-]|%[a-fA-F0-9]{2})+$"
#define RX_VALID_PATHPARMS   "^([a-zA-Z0-9!$&'\\(\\)*+=,:;@/~\\._-]|%[a-fA-F0-9]{2})+$"
#define RX_VALID_QUERYSTR    "^([a-zA-Z0-9!$&'\\(\\)*+=,:;@/?~\\._-]|%[a-fA-F0-9]{2})+$"
#define RX_VALID_FRAGMENT    "^([a-zA-Z0-9!$&'\\(\\)*+=,:;@/?~\\._-]|%[a-fA-F0-9]{2})+$"


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace url
{

using namespace blocxx;


// -------------------------------------------------------------------
ViewOptions::ViewOptions()
	: opt(ViewOptions::WITH_SCHEME     |
              ViewOptions::WITH_USERNAME   |
              ViewOptions::WITH_HOST       |
              ViewOptions::WITH_PORT       |
              ViewOptions::WITH_PATH_NAME  |
              ViewOptions::WITH_QUERY_STR  |
              ViewOptions::WITH_FRAGMENT   |
              ViewOptions::EMPTY_AUTHORITY |
              ViewOptions::EMPTY_PATH_NAME)
{}


// -------------------------------------------------------------------
ViewOptions::ViewOptions(int o)
	: opt(o)
{}


// -------------------------------------------------------------------
/*
** Behaviour configuration variables.
*/
typedef std::map< blocxx::String, blocxx::String > UrlConfig;


// -------------------------------------------------------------------
/**
 * \brief Internal data used by UrlBase.
 */
class UrlBaseData
{
public:
	UrlBaseData()
	{}

	virtual
	~UrlBaseData()
	{}

	virtual UrlBaseData *
	clone() const
	{
		return new UrlBaseData(*this);
	}

	UrlConfig       config;
	ViewOptions     vopts;

	blocxx::String  scheme;
	blocxx::String  user;
	blocxx::String  pass;
	blocxx::String  host;
	blocxx::String  port;
	blocxx::String  pathname;
	blocxx::String  pathparams;
	blocxx::String  querystr;
	blocxx::String  fragment;
};


// -------------------------------------------------------------------
/*
** Anonymous/internal utility namespace:
*/
namespace // anonymous
{

        // -----------------------------------------------------------
	inline void
	checkUrlData(const blocxx::String &data,
		     const blocxx::String &name,
		     const blocxx::String &regx,
		     bool               show=true)
	{
		if( regx.empty() || regx == "^$")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				Format(__("The %1 url component is "
				          "not allowed in this scheme"),
				       name).c_str()
			);
		}

		bool valid = false;
		try
		{
			valid = PosixRegEx(regx).match(data);
		}
		catch( ... )
		{}

		if( !valid)
		{
			if( show)
			{
				BLOCXX_THROW(UrlBadComponentException,
					Format(__("Invalid %1 URL component data '%2'."),
					       name, data).c_str()
				);
			}
			else
			{
				BLOCXX_THROW(UrlBadComponentException,
					Format(__("Invalid data in the %1 URL component."), name).c_str()
				);
			}
		}
	}

} // namespace


// -------------------------------------------------------------------
UrlBase::~UrlBase()
{
}


// -------------------------------------------------------------------
UrlBase::UrlBase()
  : m_data( new UrlBaseData())
{
	configure();
}


// -------------------------------------------------------------------
UrlBase::UrlBase(const UrlBase &url)
	: m_data( url.m_data)
{
}


// -------------------------------------------------------------------
UrlBase::UrlBase(const blocxx::String &urlString)
	: m_data( new UrlBaseData())
{
	configure();
	init( parse_url_string(urlString));
}


// -------------------------------------------------------------------
UrlBase::UrlBase(const UrlComponents &components)
	: m_data( new UrlBaseData())
{
	configure();
	init(components);
}


// -------------------------------------------------------------------
UrlBase&
UrlBase::operator = (const UrlBase& url)
{
	m_data = url.m_data;
	return *this;
}


// -------------------------------------------------------------------
UrlBase&
UrlBase::operator = (const blocxx::String &urlString)
{
	UrlBaseData   saved_data( *m_data);

	UrlComponents components( parse_url_string(urlString));
	try
	{
		init(components);
	}
	catch( ... )
	{
		// restore on failure
		m_data = saved_data.clone();
		throw;
	}
	return *this;
}


// -------------------------------------------------------------------
void
UrlBase::init(const UrlComponents &components)
{
	if( components.has_authority && config("with_authority") != "y")
	{
		BLOCXX_THROW(UrlNotAllowedException,
			__("The authority url component is not "
			   "allowed in this scheme")
		);
	}
	if( components.has_querystr && config("rx_querystr").empty())
	{
		BLOCXX_THROW(UrlNotAllowedException,
			__("The query string url component is not "
			   "allowed in this scheme")
		);
	}
	if( components.has_fragment && config("rx_fragment").empty())
	{
		BLOCXX_THROW(UrlNotAllowedException,
			__("The fragment string url component is not "
			   "allowed in this scheme")
		);
	}
	setScheme     (components.scheme);
	setAuthority  (components.authority);
	setPathData   (components.pathdata);
	setQueryString(components.querystr);
	setFragment   (components.fragment, ca_mgm::url::E_ENCODED);
}


// -------------------------------------------------------------------
void
UrlBase::configure()
{
	config("sep_pathparams",  ";");
	config("psep_pathparam",  ",");
	config("vsep_pathparam",  "=");

	config("psep_querystr",   "&");
	config("vsep_querystr",   "=");

	config("safe_username",   SAFE_CHARS_USERNAME);
	config("safe_password",   SAFE_CHARS_PASSWORD);
	config("safe_hostname",   SAFE_CHARS_HOSTNAME);
	config("safe_pathname",   SAFE_CHARS_PATHNAME);
	config("safe_pathparams", SAFE_CHARS_PATHPARAMS);
	config("safe_querystr",   SAFE_CHARS_QUERYSTR);
	config("safe_fragment",   SAFE_CHARS_FRAGMENT);

	config("rx_username",     RX_VALID_USERNAME);
	config("rx_password",     RX_VALID_PASSWORD);
	config("rx_hostipv6",     RX_VALID_HOSTIPV6);
	config("rx_hostname",     RX_VALID_HOSTNAME);
	config("rx_portnumber",   RX_VALID_PORTNUMBER);
	config("rx_pathname",     RX_VALID_PATHNAME);
        config("rx_pathparams",   RX_VALID_PATHPARMS);
        config("rx_querystr",     RX_VALID_QUERYSTR);
        config("rx_fragment",     RX_VALID_FRAGMENT);

	// y=yes (allowed)
	// n=no  (disallowed, exception if !empty)
	config("with_authority",  "y");
	config("with_port",       "y");

	// y=yes (required but don't throw if empty)
	// n=no  (not required, ignore if empty)
	// m=mandatory (exception if empty)
	config("require_host",    "n");
	config("require_pathname","n");

	// y=yes (encode 2. slash even if authority present)
	// n=no  (don't encode 2. slash if authority present)
	config("path_encode_slash2", "n");
}


// -------------------------------------------------------------------
void
UrlBase::config(const blocxx::String &opt, const blocxx::String &val)
{
	m_data->config[opt] = val;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::config(const blocxx::String &opt) const
{
	UrlConfig::const_iterator v( m_data->config.find(opt));
	if( v != m_data->config.end())
		return v->second;
	else
		return blocxx::String();
}


// -------------------------------------------------------------------
ViewOptions
UrlBase::getViewOptions() const
{
	return m_data->vopts;
}


// -------------------------------------------------------------------
void
UrlBase::setViewOptions(const ViewOptions &vopts)
{
	m_data->vopts = vopts;
}


// -------------------------------------------------------------------
void
UrlBase::clear()
{
	ca_mgm::url::UrlConfig   config(m_data->config);
	ca_mgm::url::ViewOptions vopts(m_data->vopts);
	m_data = new UrlBaseData();
	m_data->config = config;
	m_data->vopts  = vopts;
}


// -------------------------------------------------------------------
UrlBase *
UrlBase::clone() const
{
	return new UrlBase(*this);
}


// -------------------------------------------------------------------
std::vector<blocxx::String>
UrlBase::getKnownSchemes() const
{
	return std::vector<blocxx::String>();
}


// -------------------------------------------------------------------
bool
UrlBase::isKnownScheme(const blocxx::String &scheme) const
{
	String                      lscheme( String(scheme).toLowerCase());
	std::vector<blocxx::String>                 schemes( getKnownSchemes());
	std::vector<blocxx::String>::const_iterator s;

	for(s=schemes.begin(); s!=schemes.end(); ++s)
	{
		if( lscheme == String(*s).toLowerCase())
			return true;
	}
	return false;
}


// -------------------------------------------------------------------
bool
UrlBase::isValidScheme(const blocxx::String &scheme) const
{
	bool valid = false;
	try
	{
		checkValidScheme(scheme, ca_mgm::url::E_ENCODED);
		valid = true;
	}
	catch( ... )
	{}

	if(valid)
	{
		String      lscheme( String(scheme).toLowerCase());
		std::vector<blocxx::String> schemes( getKnownSchemes());

		if( schemes.empty())
			return true;

		std::vector<blocxx::String>::const_iterator s;
		for(s=schemes.begin(); s!=schemes.end(); ++s)
		{
			if( lscheme == String(*s).toLowerCase())
				return true;
		}
	}
	return false;
}


// -------------------------------------------------------------------
bool
UrlBase::isValid() const
{
	/*
	** scheme is the only mandatory component
	** for all url's and is already verified,
	** (except for empty Url instances), so
	** Url with empty scheme is never valid.
	*/
	if( getScheme().empty())
		return false;

	blocxx::String host( getHost(ca_mgm::url::E_ENCODED));
	if( host.empty() && config("require_host")     != "n")
		return false;

	blocxx::String path( getPathName(ca_mgm::url::E_ENCODED));
	if( path.empty() && config("require_pathname") != "n")
		return false;

	/*
	** path has to begin with "/" if authority avaliable
	** if host is set after the pathname, we can't throw
	*/
	if( !host.empty() && !path.empty() && path.charAt(0) != '/')
		return false;

	return true;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::toString() const
{
	return toString(getViewOptions());
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::toString(const ca_mgm::url::ViewOptions &opts) const
{
	blocxx::String   url;
	UrlBaseData   tmp;

	if( opts.has(ViewOptions::WITH_SCHEME))
	{
		tmp.scheme = getScheme();
		if( !tmp.scheme.empty())
		{
			url += tmp.scheme + ":";

			if( opts.has(ViewOptions::WITH_HOST))
			{
				tmp.host = getHost(ca_mgm::url::E_ENCODED);
				if( !tmp.host.empty())
				{
					url += "//";

					if( opts.has(ViewOptions::WITH_USERNAME))
					{
						tmp.user = getUsername(ca_mgm::url::E_ENCODED);
						if( !tmp.user.empty())
						{
							url += tmp.user;

							if( opts.has(ViewOptions::WITH_PASSWORD))
							{
								tmp.pass = getPassword(ca_mgm::url::E_ENCODED);
								if( !tmp.pass.empty())
								{
									url += ":" + tmp.pass;
								}
							}

							url += "@";
						}
					}

					url += tmp.host;

					if( opts.has(ViewOptions::WITH_PORT))
					{
						tmp.port = getPort();
						if( !tmp.port.empty())
						{
							url += ":" + tmp.port;
						}
					}
				}
				else if( opts.has(ViewOptions::EMPTY_AUTHORITY))
				{
					url += "//";
				}
			}
			else if( opts.has(ViewOptions::EMPTY_AUTHORITY))
			{
				url += "//";
			}
		}
	}

	if( opts.has(ViewOptions::WITH_PATH_NAME))
	{
		tmp.pathname = getPathName(ca_mgm::url::E_ENCODED);
		if( !tmp.pathname.empty())
		{
			if(url.indexOf("/") != String::npos)
			{
				// Url contains authority (that may be empty),
				// we may need a rewrite of the encoded path.
				tmp.pathname = cleanupPathName(tmp.pathname, true);
				if(tmp.pathname.charAt(0) != '/')
				{
					url += "/";
				}
			}
			url += tmp.pathname;

			if( opts.has(ViewOptions::WITH_PATH_PARAMS))
			{
				tmp.pathparams = getPathParams();
				if( !tmp.pathparams.empty())
				{
					url += ";" + tmp.pathparams;
				}
				else if( opts.has(ViewOptions::EMPTY_PATH_PARAMS))
				{
					url += ";";
				}
			}
		}
		else if( opts.has(ViewOptions::EMPTY_PATH_NAME)
		         && url.indexOf("/") != String::npos)
		{
			url += "/";
			if( opts.has(ViewOptions::EMPTY_PATH_PARAMS))
			{
				url += ";";
			}
		}
	}

	if( opts.has(ViewOptions::WITH_QUERY_STR))
	{
		tmp.querystr = getQueryString();
		if( !tmp.querystr.empty())
		{
			url += "?" + tmp.querystr;
		}
		else if( opts.has(ViewOptions::EMPTY_QUERY_STR))
		{
			url += "?";
		}
	}

	if( opts.has(ViewOptions::WITH_FRAGMENT))
	{
		tmp.fragment = getFragment(ca_mgm::url::E_ENCODED);
		if( !tmp.fragment.empty())
		{
			url += "#" + tmp.fragment;
		}
		else if( opts.has(ViewOptions::EMPTY_FRAGMENT))
		{
			url += "#";
		}
	}

	return url;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getScheme() const
{
	return m_data->scheme;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getAuthority() const
{
	blocxx::String str;
	if( !getHost(ca_mgm::url::E_ENCODED).empty())
	{
		if( !getUsername(ca_mgm::url::E_ENCODED).empty())
		{
			str = getUsername(ca_mgm::url::E_ENCODED);
			if( !getPassword(ca_mgm::url::E_ENCODED).empty())
			{
				str += ":" + getPassword(ca_mgm::url::E_ENCODED);
			}
			str += "@";
		}

		str += getHost(ca_mgm::url::E_ENCODED);
		if( !getPort().empty())
		{
			str += ":" + getPort();
		}
	}
	return str;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPathData() const
{
	return getPathName(ca_mgm::url::E_ENCODED) +
	                   config("sep_pathparams") +
	                   getPathParams();
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getQueryString() const
{
	return m_data->querystr;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getFragment(EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_DECODED)
		return ca_mgm::url::decode(m_data->fragment);
	else
		return m_data->fragment;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getUsername(EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_DECODED)
		return ca_mgm::url::decode(m_data->user);
	else
		return m_data->user;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPassword(EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_DECODED)
		return ca_mgm::url::decode(m_data->pass);
	else
		return m_data->pass;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getHost(EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_DECODED)
		return ca_mgm::url::decode(m_data->host);
	else
		return m_data->host;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPort() const
{
	return m_data->port;
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPathName(EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_DECODED)
		return ca_mgm::url::decode(m_data->pathname);
	else
		return cleanupPathName(m_data->pathname);
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPathParams() const
{
	return m_data->pathparams;
}


// -------------------------------------------------------------------
std::vector<blocxx::String>
UrlBase::getPathParamsArray() const
{
	if( config("psep_pathparam").empty())
	{
		return std::vector<blocxx::String>(1, getPathParams());
	}
	else
	{
		return ca_mgm::url::split(
			getPathParams(),
			config("psep_pathparam")
		);
	}
}


// -------------------------------------------------------------------
ca_mgm::url::ParamMap
UrlBase::getPathParamsMap(EEncoding eflag) const
{
	if( config("psep_pathparam").empty() ||
	    config("vsep_pathparam").empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Path parameter parsing is not supported for this URL.")
		);
	}
	return ca_mgm::url::split(
		getPathParams(),
		config("psep_pathparam"),
		config("vsep_pathparam"),
		eflag
	);
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getPathParam(const blocxx::String &param, EEncoding eflag) const
{
	ca_mgm::url::ParamMap pmap( getPathParamsMap( eflag));
	ca_mgm::url::ParamMap::const_iterator i( pmap.find(param));

	return i != pmap.end() ? i->second : blocxx::String();
}


// -------------------------------------------------------------------
std::vector<blocxx::String>
UrlBase::getQueryStringArray() const
{
	if( config("psep_querystr").empty())
	{
		return std::vector<blocxx::String>(1, getQueryString());
	}
	else
	{
		return ca_mgm::url::split(
			getQueryString(),
			config("psep_querystr")
		);
	}
}


// -------------------------------------------------------------------
ca_mgm::url::ParamMap
UrlBase::getQueryStringMap(EEncoding eflag) const
{
	if( config("psep_querystr").empty() ||
	    config("vsep_querystr").empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Query string parsing is not supported for this URL.")
		);
	}
	return ca_mgm::url::split(
		getQueryString(),
		config("psep_querystr"),
		config("vsep_querystr"),
		eflag
	);
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::getQueryParam(const blocxx::String &param, EEncoding eflag) const
{
	ca_mgm::url::ParamMap pmap( getQueryStringMap( eflag));
	ca_mgm::url::ParamMap::const_iterator i( pmap.find(param));

	return i != pmap.end() ? i->second : blocxx::String();
}


// -------------------------------------------------------------------
void
UrlBase::setScheme(const blocxx::String &scheme)
{
	if( isValidScheme(scheme))
	{
		m_data->scheme = String(scheme).toLowerCase();
	}
	else
	if( scheme.empty())
	{
		BLOCXX_THROW(UrlBadComponentException,
			__("The URL scheme is a required component.")
		);
	}
	else
	{
		BLOCXX_THROW(UrlBadComponentException,
			Format(__("Invalid URL scheme '%1'."),
			       scheme).c_str()
		);
	}
}


// -------------------------------------------------------------------
void
UrlBase::setAuthority(const blocxx::String &authority)
{
	UrlAuthority tmp( parse_url_authority(authority));

	setUsername( tmp.user, ca_mgm::url::E_ENCODED);
	setPassword( tmp.pass, ca_mgm::url::E_ENCODED);
	setHost    ( tmp.host, ca_mgm::url::E_ENCODED);
	setPort    ( tmp.port);
}


// -------------------------------------------------------------------
void
UrlBase::setPathData(const blocxx::String &pathdata)
{
	size_t      pos = blocxx::String::npos;
	blocxx::String sep(config("sep_pathparams"));

	if( !sep.empty())
		pos = pathdata.indexOf(sep);

	if( pos != String::npos)
	{
		setPathName(pathdata.substring(0, pos),
		            ca_mgm::url::E_ENCODED);
		setPathParams(pathdata.substring(pos + 1));
	}
	else
	{
		setPathName(pathdata, ca_mgm::url::E_ENCODED);
		setPathParams("");
	}
}


// -------------------------------------------------------------------
void
UrlBase::setQueryString(const blocxx::String &querystr)
{
	if( querystr.empty())
	{
		m_data->querystr = querystr;
	}
	else
	{
		checkValidQueryStr(querystr, ca_mgm::url::E_ENCODED);

		m_data->querystr = querystr;
	}
}


// -------------------------------------------------------------------
void
UrlBase::setFragment(const blocxx::String &fragment, EEncoding eflag)
{
	if( fragment.empty())
	{
		m_data->fragment = fragment;
	}
	else
	{
		checkValidFragment(fragment, eflag);

		if(eflag == ca_mgm::url::E_ENCODED)
		{
			m_data->fragment = fragment;
		}
		else
		{
			m_data->fragment = ca_mgm::url::encode(
				fragment, config("safe_password")
			);
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::setUsername(const blocxx::String &user, EEncoding eflag)
{
	if( user.empty())
	{
		m_data->user = user;
	}
	else
	{
		if( config("with_authority") != "y")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The username component is not "
				   "allowed in this scheme")
			);
		}

		checkValidUser(user, eflag);

		if(eflag == ca_mgm::url::E_ENCODED)
		{
			m_data->user = user;
		}
		else
		{
			m_data->user = ca_mgm::url::encode(
				user, config("safe_username")
			);
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::setPassword(const blocxx::String &pass, EEncoding eflag)
{
	if( pass.empty())
	{
		m_data->pass = pass;
	}
	else
	{
		if( config("with_authority") != "y")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The password component is not "
				   "allowed in this scheme")
			);
		}

		checkValidPass(pass, eflag);

		if(eflag == ca_mgm::url::E_ENCODED)
		{
			m_data->pass = pass;
		}
		else
		{
			m_data->pass = ca_mgm::url::encode(
				pass, config("safe_password")
			);
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::setHost(const blocxx::String &host, EEncoding eflag)
{
	if( host.empty())
	{
		if(config("require_host") == "m")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The URL scheme requires a host.")
			);
		}
		m_data->host = host;
	}
	else
	{
		if( config("with_authority") != "y")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The hostname component is not "
				   "allowed in this scheme")
			);
		}

		checkValidHost( host, eflag);

		if( host.charAt(0) == '[')
		{
			if( host.charAt(1) == 'v')
			{
				// Hmm... checkValidHost may be reimplemented
				// and supports the IPvFuture brace format.
				if( eflag == ca_mgm::url::E_ENCODED)
				{
					m_data->host = host;
				}
				else
				{
					m_data->host = ca_mgm::url::encode(
						host, SAFE_CHARS_HOSTNAME
					);
				}
			}
			else
			{
				// use upper case in IPv6 addresses
				m_data->host = String(host).toUpperCase();
			}
		}
		else
		{
			if(eflag == ca_mgm::url::E_ENCODED)
			{
				m_data->host = ca_mgm::url::encode(
					ca_mgm::url::decode(host).toLowerCase(),
					SAFE_CHARS_HOSTNAME
				);
			}
			else
			{
				m_data->host = ca_mgm::url::encode(
					String(host).toLowerCase(),
					SAFE_CHARS_HOSTNAME
				);
			}
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::setPort(const blocxx::String &port)
{
	if( port.empty())
	{
		m_data->port = port;
	}
	else
	{
		if( config("with_authority") != "y" ||
		    config("with_port")      != "y")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The port number component is not "
				   "allowed in this scheme")
			);
		}

		checkValidPort(port, ca_mgm::url::E_ENCODED);

		m_data->port = port;
	}
}


// -------------------------------------------------------------------
void
UrlBase::setPathName(const blocxx::String &path, EEncoding eflag)
{
	if( path.empty())
	{
		if(config("require_pathname") == "m")
		{
			BLOCXX_THROW(UrlNotAllowedException,
				__("The URL scheme requires a path.")
			);
		}
		m_data->pathname = path;
	}
	else
	{
		checkValidPathName(path, eflag);

		if(eflag == ca_mgm::url::E_ENCODED)
		{
			m_data->pathname = cleanupPathName(path);
		}
		else
		{
			m_data->pathname = cleanupPathName(
				ca_mgm::url::encode(
					path, config("safe_pathname")
				)
			);
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::setPathParams(const blocxx::String &params)
{
	if( params.empty())
	{
		m_data->pathparams = params;
	}
	else
	{
		checkValidPathParams(params, ca_mgm::url::E_ENCODED);

		m_data->pathparams = params;
	}
}


// -------------------------------------------------------------------
void
UrlBase::setPathParamsArray(const std::vector<blocxx::String> &parray)
{
	setPathParams(
		ca_mgm::url::join(
			parray,
			config("psep_pathparam")
		)
	);
}


// -------------------------------------------------------------------
void
UrlBase::setPathParamsMap(const ca_mgm::url::ParamMap &pmap)
{
	if( config("psep_pathparam").empty() ||
	    config("vsep_pathparam").empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Path parameter parsing is not supported for this URL.")
		);
	}
	setPathParams(
		ca_mgm::url::join(
			pmap,
			config("psep_pathparam"),
			config("vsep_pathparam"),
			config("safe_pathparams")
		)
	);
}


// -------------------------------------------------------------------
void
UrlBase::setPathParam(const blocxx::String &param, const blocxx::String &value)
{
	ca_mgm::url::ParamMap pmap( getPathParamsMap(ca_mgm::url::E_DECODED));
	pmap[param] = value;
	setPathParamsMap(pmap);
}


// -------------------------------------------------------------------
void
UrlBase::setQueryStringArray(const std::vector<blocxx::String> &qarray)
{
	setQueryString(
		ca_mgm::url::join(
			qarray,
			config("psep_querystr")
		)
	);
}


// -------------------------------------------------------------------
void
UrlBase::setQueryStringMap(const ca_mgm::url::ParamMap &pmap)
{
	if( config("psep_querystr").empty() ||
	    config("vsep_querystr").empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Query string parsing is not supported for this URL.")
		);
	}
	setQueryString(
		ca_mgm::url::join(
			pmap,
			config("psep_querystr"),
			config("vsep_querystr"),
			config("safe_querystr")
		)
	);
}

// -------------------------------------------------------------------
void
UrlBase::setQueryParam(const blocxx::String &param, const blocxx::String &value)
{
	ca_mgm::url::ParamMap pmap( getQueryStringMap(ca_mgm::url::E_DECODED));
	pmap[param] = value;
	setQueryStringMap(pmap);
}


// -------------------------------------------------------------------
blocxx::String
UrlBase::cleanupPathName(const blocxx::String &path) const
{
	bool authority = !getHost(ca_mgm::url::E_ENCODED).empty();
	return cleanupPathName(path, authority);
}

// -------------------------------------------------------------------
blocxx::String
UrlBase::cleanupPathName(const blocxx::String &path, bool authority) const
{
	blocxx::String copy( path);

	// decode the first slash if it is encoded ...
	if(copy.length() >= 3 && copy.charAt(0) != '/' &&
	   copy.substring(0, 3).toLowerCase() == "%2f")
	{
		copy = "/" + copy.substring(3);
	}

	// if path begins with a double slash ("//"); encode the second
	// slash [minimal and IMO sufficient] before the first path
	// segment, to fulfill the path-absolute rule of RFC 3986
	// disallowing a "//" if no authority is present.
	if( authority)
	{
		//
		// rewrite of "//" to "/%2f" not required, use config
		//
		if(config("path_encode_slash2") == "y")
		{
			// rewrite "//" ==> "/%2f"
			if(copy.length() >= 2 && copy.charAt(0) == '/' && copy.charAt(1) == '/')
			{
				copy = "/%2F" + copy.substring(2);
			}
		}
		else
		{
			// rewrite "/%2f" ==> "//"
			if(copy.length() >= 4 && copy.charAt(0) == '/' &&
			   copy.substring(1, 4).toLowerCase() == "%2f")
			{
				copy = "//" + copy.substring(4);
			}
		}
	}
	else
	{
		// rewrite of "//" to "/%2f" is required (no authority)
		if(copy.length() >= 2 && copy.charAt(0) == '/' && copy.charAt(1) == '/')
		{
			copy = "/%2F" + copy.substring(2);
		}
	}
	return copy;
}

// -------------------------------------------------------------------
void
UrlBase::checkValidScheme(const blocxx::String  &scheme,
                          ca_mgm::url::EEncoding eflag) const
{
	(void)eflag; // scheme never needs percent-encoding

	checkUrlData(scheme, "scheme", RX_VALID_SCHEME, true);
}


// -------------------------------------------------------------------
void
UrlBase::checkValidUser(const blocxx::String  &user,
                        ca_mgm::url::EEncoding eflag) const
{
	if( eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(user, "username", config("rx_username"), true);
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidPass(const blocxx::String  &pass,
                        ca_mgm::url::EEncoding eflag) const
{
	if( eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(pass, "password", config("rx_password"), false);
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidHost(const blocxx::String  &host,
                        ca_mgm::url::EEncoding eflag) const
{
	bool valid = false;
	try
	{
		if( host.charAt(0) == '[')
		{
			// We don't support the IP-Literal "[v<HEX> ... ]" format
			if( host.charAt(1) == 'v')
			{
				BLOCXX_THROW(UrlBadComponentException,
					__("The IPvFuture URL host format is not supported.")
				);
			}

			checkUrlData(host, "ipv6 host", config("rx_hostipv6"));

			struct in6_addr ip;
			blocxx::String temp( host.substring(1, host.length()-2));
			valid = inet_pton(AF_INET6, temp.c_str(), &ip) > 0;
		}
		else
		{
			// matches also IPv4 dotted-decimal adresses...
			if( eflag == ca_mgm::url::E_DECODED)
			{
				checkUrlData(host, "hostname", config("rx_hostname"));
				valid = true;
			}
			else
			{
				blocxx::String temp( ca_mgm::url::decode(host));
				checkUrlData(temp, "hostname", config("rx_hostname"));
				valid = true;
			}
		}
	}
	catch( ... )
	{
		valid = false;
	}

	if( !valid)
	{
		BLOCXX_THROW(UrlBadComponentException,
			Format(__("Invalid hostname URL component data '%1'."),
			       host).c_str()
		);
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidPort(const blocxx::String  &port,
                        ca_mgm::url::EEncoding eflag) const
{
	(void)eflag; // port never needs percent-encoding

	bool valid = false;
	try
	{
		checkUrlData(port, "port number", config("rx_portnumber"));

		blocxx::UInt16 pnum = port.toUInt16();
		valid = pnum >= 1;
	}
	catch( ... )
	{
		valid = false;
	}

	if( !valid)
	{
		BLOCXX_THROW(UrlBadComponentException,
			Format(__("Invalid port number URL component data '%1'."),
			       port).c_str()
		);
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidPathName(const blocxx::String  &path,
                            ca_mgm::url::EEncoding eflag) const
{
	if(eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(path, "path name", config("rx_pathname"));

		if( !getHost(ca_mgm::url::E_ENCODED).empty())
		{
			// has to begin with a "/". For consistency with
			// setPathName while the host is empty, we allow
			// it in encoded ("%2f") form - cleanupPathName()
			// will fix / decode the first slash if needed.
			if(!(path.charAt(0) == '/' || (path.length() >= 3 &&
			   path.substring(0, 3).toLowerCase() == "%2f")))
			{
				BLOCXX_THROW(UrlNotAllowedException,
					__("A relative path is not allowed if authority exists.")
				);
			}
		}

	}
	else //     ca_mgm::url::E_DECODED
	{
		if( !getHost(ca_mgm::url::E_ENCODED).empty())
		{
			if(path.charAt(0) != '/')
			{
				BLOCXX_THROW(UrlNotAllowedException,
					__("A relative path is not allowed if authority exists.")
				);
			}
		}
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidPathParams(const blocxx::String  &params,
                              ca_mgm::url::EEncoding eflag) const
{
	if( eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(params, "path parameters", config("rx_pathparams"));
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidQueryStr(const blocxx::String  &querystr,
                            ca_mgm::url::EEncoding eflag) const
{
	if( eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(querystr, "query string", config("rx_querystr"));
	}
}


// -------------------------------------------------------------------
void
UrlBase::checkValidFragment(const blocxx::String  &fragment,
                            ca_mgm::url::EEncoding eflag) const
{
	if( eflag == ca_mgm::url::E_ENCODED)
	{
		checkUrlData(fragment, "fragment string", config("rx_fragment"));
	}
}


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
