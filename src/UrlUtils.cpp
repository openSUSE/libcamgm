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

  File:       UrlUtils.cpp

  Maintainer: Marius Tomaschewski

/-*/

#include <ca-mgm/UrlUtils.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/PosixRegEx.hpp>

#include "Utils.hpp"

#include <stdlib.h>   // strtol
#include <cctype>     // isxdigit


// -----------------------------------------------------------------------
/*
** url            = [scheme:] [//authority] /path [?query] [#fragment]
*/
#define RX_SPLIT_URL		\
	"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)([?]([^#]*))?(#(.*))?"


// -----------------------------------------------------------------------
/*
** url authority  = [user [:password] @ ] host [:port]
*/
#define RX_SPLIT_URL_AUTHORITY	\
	"^(([^:@]*)([:]([^@]*))?@)?(\\[[^]]+\\]|[^:]+)?([:](.*))?"


// -------------------------------------------------------------------
namespace CA_MGM_NAMESPACE
{
namespace url
{

// -------------------------------------------------------------------
CA_MGM_DEFINE_EXCEPTION (Url);
CA_MGM_DEFINE_EXCEPTION2(UrlParsing,      UrlException);
CA_MGM_DEFINE_EXCEPTION2(UrlDecoding,     UrlException);
CA_MGM_DEFINE_EXCEPTION2(UrlBadComponent, UrlException);
CA_MGM_DEFINE_EXCEPTION2(UrlNotAllowed,   UrlException);
CA_MGM_DEFINE_EXCEPTION2(UrlNotSupported, UrlException);


// -------------------------------------------------------------------
namespace // anonymous
{

	inline size_t
	find_first_not_of(const ca_mgm::ByteBuffer &src,
	                  const std::string    &set,
	                  size_t                   off = 0)
	{
		for(size_t pos = off; pos < src.size(); pos++)
		{
			if( set.find_first_of(src.at(pos)) == std::string::npos)
			{
				return pos;
			}
		}
		return std::string::npos;
	}

} // anonymous namespace


// -------------------------------------------------------------------
std::string
encode(const std::string &str, const std::string  &safe,
                                  ca_mgm::url::EEncoding eflag)
{
	if( str.empty())
	{
		return std::string();
	}
	else
	{
		return encode_buf(
			ByteBuffer(str.c_str(), str.length()),
			safe, eflag
		);
	}
}


// -------------------------------------------------------------------
std::string
encode_buf(const ca_mgm::ByteBuffer &buf, const std::string  &safe,
                                         ca_mgm::url::EEncoding eflag)
{
	if( buf.empty())
	{
		return std::string();
	}

	std::string skip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	                 "abcdefghijklmnopqrstuvwxyz"
	                 "0123456789.~_-");
	std::string more(":/?#[]@!$&'()*+,;=");
	std::string out;
	size_t beg, pos, len;

	for(size_t i=0; i<safe.length(); i++)
	{
		if( more.find_first_of(safe[i]) != std::string::npos)
			skip += safe[i];
	}

	len = buf.size();
	beg = 0;
	while( beg < len)
	{
		pos = find_first_not_of(buf, skip, beg);
		if(pos != std::string::npos)
		{
			if( pos > beg)
			{
				out += std::string(buf.data() + beg, pos - beg);
			}

			if( eflag == E_ENCODED &&
			    pos + 2 < len      &&
			    buf.at(pos) == '%' &&
			    ::isxdigit(buf.at(pos + 1)) &&
			    ::isxdigit(buf.at(pos + 2)))
			{
				out += std::string(buf.data() + pos, 3);
				beg = pos + 3;
			}
			else
			{
				out += encode_octet( buf.at(pos));
				beg = pos + 1;
			}
		}
		else
		{
			out += std::string(buf.data() + beg, len - beg);
			beg = len;
		}
	}
	return out;
}


// -------------------------------------------------------------------
std::string
decode(const std::string &str)
{
	return std::string( ByteBuffer(decode_buf(str, false)).data());
}


// -------------------------------------------------------------------
ca_mgm::ByteBuffer
decode_buf(const std::string &str, bool allowNUL)
{
	size_t      pos, ins, len;
	ByteBuffer  out(str.c_str(), str.length());

	len = str.length();
	pos = ins = 0;
	while(pos < len)
	{
		out[ins] = str.at(pos);
		if( pos + 2 < len && out[pos] == '%')
		{
			int c = decode_octet(str.c_str() + pos + 1);
			switch(c)
			{
				case -1:
					// not a hex noted octet...
				break;

				case 0:
					// is a %00 octet allowed ?
					if( !allowNUL)
					{
						CA_MGM_THROW(UrlDecodingException,
							__("The URL-encoded string may not contain a NULL byte.")
						);
					}
				default:
					// other octets are fine...
					out[ins] = c;
					pos += 2;
				break;
			}
		}
		pos++;
		ins++;
	}
	if( ins < pos)
		return ByteBuffer(out.data(), ins);
	else
		return out;
}


// -------------------------------------------------------------------
std::string
encode_octet(const unsigned char c)
{
	static const unsigned char tab[] = "0123456789ABCDEF";
	unsigned char      out[4];

	out[0] = '%';
	out[1] = tab[0x0f & (c >> 4)];
	out[2] = tab[0x0f & c];
	out[3] = '\0';

	//snprintf(out, sizeof(out), "%%%02X", c);
	return std::string((char *)out);
}


// -------------------------------------------------------------------
int
decode_octet(const char *hex)
{
	if(hex && ::isxdigit(hex[0]) && ::isxdigit(hex[1]))
	{
		char x[3] = { hex[0], hex[1], '\0'};
		return 0xff & ::strtol(x, NULL, 16);
	}
	else
	{
		return -1;
	}
}


// -------------------------------------------------------------------
std::vector<std::string>
split(const std::string &pstr,
      const std::string &psep)
{
	if( psep.empty())
	{
		CA_MGM_THROW(UrlNotSupportedException,
			__("Invalid split separator character.")
		);
	}

	std::vector<std::string> params;
	size_t beg, pos, len;

	len = pstr.length();
	beg = 0;

	while( beg < len)
	{
		pos = pstr.find_first_of(psep, beg);
		if(pos != std::string::npos)
		{
			params.push_back( pstr.substr(beg, pos - beg));
			beg = pos + 1;
		}
		else
		{
			params.push_back( pstr.substr(beg, len - beg));
			beg = len;
		}
	}
	return params;
}


// -------------------------------------------------------------------
ca_mgm::url::ParamMap
split(const std::string &str,
      const std::string &psep,
      const std::string &vsep,
      EEncoding         eflag)
{
	if( psep.empty() || vsep.empty())
	{
		CA_MGM_THROW(UrlNotSupportedException,
			__("Invalid split separator character.")
		);
	}

	std::vector<std::string>                 params( split(str, psep));
	std::vector<std::string>::const_iterator piter;
	std::string              key, val;
	size_t                      pos;
	ParamMap                    pmap;

	for( piter = params.begin(); piter != params.end(); ++piter)
	{
		pos = piter->find_first_of(vsep);
		if(pos != std::string::npos)
		{
			if( eflag == E_DECODED)
			{
				key = url::decode(piter->substr(0, pos));
				val = url::decode(piter->substr(pos + 1));
				pmap[ key ] = val;
			}
			else
			{
				key = piter->substr(0, pos);
				val = piter->substr(pos + 1);
				pmap[ key ] = val;
			}
		}
		else
		{
			if( eflag == E_DECODED)
			{
				pmap[ url::decode(*piter) ] = "";
			}
			else
			{
				pmap[ *piter ] = "";
			}
		}
	}
	return pmap;
}


// -------------------------------------------------------------------
std::string
join(const std::vector<std::string> &params,
     const std::string      &psep)
{
	std::string                      str;
	std::vector<std::string>::const_iterator p( params.begin());

	if( p != params.end())
	{
		str = *p;
		while( ++p != params.end())
		{
			str += psep + *p;
		}
	}
	return str;
}


// -------------------------------------------------------------------
std::string
join(const ca_mgm::url::ParamMap &pmap,
     const std::string       &psep,
     const std::string       &vsep,
     const std::string       &safe)
{
	if( psep.empty() || vsep.empty())
	{
		CA_MGM_THROW(UrlNotSupportedException,
			__("Invalid parameter map join separator character.")
		);
	}

	std::string join_safe;
	for(size_t i=0; i<safe.length(); i++)
	{
		if( psep.find_first_of(safe[i]) == std::string::npos &&
		    vsep.find_first_of(safe[i]) == std::string::npos)
		{
			join_safe += safe[i];
		}
	}
	std::string           str;
	ParamMap::const_iterator p( pmap.begin());

	if( p != pmap.end())
	{
		str = encode(p->first, join_safe);
		if( !p->second.empty())
			str += vsep + encode(p->second, join_safe);

		while( ++p != pmap.end())
		{
			str += psep + encode(p->first, join_safe);
			if( !p->second.empty())
				str +=  vsep + encode(p->second, join_safe);
		}
	}

	return str;
}


// -------------------------------------------------------------------
UrlComponents
parse_url_string(const std::string &url)
{
	std::vector<std::string> cap;
	try
	{
		PosixRegEx reg(RX_SPLIT_URL);
		cap = reg.capture(url);
	}
	catch(...)
	{}

	if( cap.size() == 10)
	{
#if defined(SPLIT_URL_TRACE)
		for(size_t n=0; n<cap.size(); n++)
		{
			LOGIT_DEBUG("split_url_string: cap["
			            << n << "]='" << cap[n] << "'");
		}
#endif
		UrlComponents ret;
		ret.has_scheme   = !cap[1].empty();
		ret.scheme       =  cap[2];

		ret.has_authority= !cap[3].empty();
		ret.authority    =  cap[4];

		ret.pathdata     =  cap[5];

		ret.has_querystr = !cap[6].empty();
		ret.querystr     =  cap[7];

		ret.has_fragment = !cap[8].empty();
		ret.fragment     =  cap[9];

		return ret;
	}
	else
	{
                CA_MGM_THROW(UrlParsingException,
			__("Unable to parse main URL components.")
		);
	}
}


// -------------------------------------------------------------------
UrlAuthority
parse_url_authority(const std::string &authority)
{
	std::vector<std::string> cap;
	try
	{
		PosixRegEx reg(RX_SPLIT_URL_AUTHORITY);
		cap = reg.capture(authority);
	}
	catch(...)
	{}

	if( cap.size() == 8)
	{
#if defined(SPLIT_URL_TRACE)
		for(size_t n=0; n<cap.size(); n++)
		{
			LOGIT_DEBUG("split_url_authority: cap["
			            << n << "]='" << cap[n] << "'");
		}
#endif
		UrlAuthority ret;
		ret.has_user = !cap[1].empty();
		ret.user     =  cap[2];

		ret.has_pass = !cap[3].empty();
		ret.pass     =  cap[4];

		ret.host     =  cap[5];

		ret.has_port = !cap[6].empty();
		ret.port     =  cap[7];

		return ret;
	}
	else
	{
                CA_MGM_THROW(UrlParsingException,
			__("Unable to parse URL authority components.")
		);
	}
}


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of CA_MGM_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
