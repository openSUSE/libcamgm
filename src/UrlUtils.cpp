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

#include <limal/UrlUtils.hpp>
#include <blocxx/Format.hpp>
#include <blocxx/PosixRegEx.hpp>

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
namespace LIMAL_NAMESPACE
{
namespace url
{

using namespace blocxx;


// -------------------------------------------------------------------
BLOCXX_DEFINE_EXCEPTION (Url);
BLOCXX_DEFINE_EXCEPTION2(UrlParsing,      UrlException);
BLOCXX_DEFINE_EXCEPTION2(UrlDecoding,     UrlException);
BLOCXX_DEFINE_EXCEPTION2(UrlBadComponent, UrlException);
BLOCXX_DEFINE_EXCEPTION2(UrlNotAllowed,   UrlException);
BLOCXX_DEFINE_EXCEPTION2(UrlNotSupported, UrlException);


// -------------------------------------------------------------------
namespace // anonymous
{

	inline size_t
	find_first_not_of(const ca_mgm::ByteBuffer &src,
	                  const blocxx::String    &set,
	                  size_t                   off = 0)
	{
		for(size_t pos = off; pos < src.size(); pos++)
		{
			if( set.indexOf(src.at(pos)) == String::npos)
			{
				return pos;
			}
		}
		return blocxx::String::npos;
	}

} // anonymous namespace


// -------------------------------------------------------------------
blocxx::String
encode(const blocxx::String &str, const blocxx::String  &safe,
                                  ca_mgm::url::EEncoding eflag)
{
	if( str.empty())
	{
		return String();
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
blocxx::String
encode_buf(const ca_mgm::ByteBuffer &buf, const blocxx::String  &safe,
                                         ca_mgm::url::EEncoding eflag)
{
	if( buf.empty())
	{
		return String();
	}

	String skip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	            "abcdefghijklmnopqrstuvwxyz"
	            "0123456789.~_-");
	String more(":/?#[]@!$&'()*+,;=");
	String out;
	size_t beg, pos, len;

	for(size_t i=0; i<safe.length(); i++)
	{
		if( more.indexOf(safe[i]) != String::npos)
			skip.concat(safe[i]);
	}

	len = buf.size();
	beg = 0;
	while( beg < len)
	{
		pos = find_first_not_of(buf, skip, beg);
		if(pos != String::npos)
		{
			if( pos > beg)
			{
				out.concat(String(buf.data() + beg, pos - beg));
			}

			if( eflag == E_ENCODED &&
			    pos + 2 < len      &&
			    buf.at(pos) == '%' &&
			    ::isxdigit(buf.at(pos + 1)) &&
			    ::isxdigit(buf.at(pos + 2)))
			{
				out.concat(String(buf.data() + pos, 3));
				beg = pos + 3;
			}
			else
			{
				out.concat( encode_octet( buf.at(pos)));
				beg = pos + 1;
			}
		}
		else
		{
			out.concat(String(buf.data() + beg, len - beg));
			beg = len;
		}
	}
	return out;
}


// -------------------------------------------------------------------
blocxx::String
decode(const blocxx::String &str)
{
	return String( ByteBuffer(decode_buf(str, false)).data());
}


// -------------------------------------------------------------------
ca_mgm::ByteBuffer
decode_buf(const blocxx::String &str, bool allowNUL)
{
	size_t      pos, ins, len;
	ByteBuffer  out(str.c_str(), str.length());

	len = str.length();
	pos = ins = 0;
	while(pos < len)
	{
		out[ins] = str.charAt(pos);
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
						BLOCXX_THROW(UrlDecodingException,
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
blocxx::String
encode_octet(const unsigned char c)
{
	static const unsigned char tab[] = "0123456789ABCDEF";
	unsigned char      out[4];

	out[0] = '%';
	out[1] = tab[0x0f & (c >> 4)];
	out[2] = tab[0x0f & c];
	out[3] = '\0';

	//snprintf(out, sizeof(out), "%%%02X", c);
	return blocxx::String((char *)out);
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
blocxx::StringArray
split(const blocxx::String &pstr,
      const blocxx::String &psep)
{
	if( psep.empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Invalid split separator character.")
		);
	}

	StringArray params;
	size_t beg, pos, len;

	len = pstr.length();
	beg = 0;

	while( beg < len)
	{
		pos = pstr.indexOf(psep, beg);
		if(pos != String::npos)
		{
			params.push_back( pstr.substring(beg, pos - beg));
			beg = pos + 1;
		}
		else
		{
			params.push_back( pstr.substring(beg, len - beg));
			beg = len;
		}
	}
	return params;
}


// -------------------------------------------------------------------
ca_mgm::url::ParamMap
split(const blocxx::String &str,
      const blocxx::String &psep,
      const blocxx::String &vsep,
      EEncoding         eflag)
{
	if( psep.empty() || vsep.empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Invalid split separator character.")
		);
	}

	StringArray                 params( split(str, psep));
	StringArray::const_iterator piter;
	blocxx::String              key, val;
	size_t                      pos;
	ParamMap                    pmap;

	for( piter = params.begin(); piter != params.end(); ++piter)
	{
		pos = piter->indexOf(vsep);
		if(pos != String::npos)
		{
			if( eflag == E_DECODED)
			{
				key = url::decode(piter->substring(0, pos));
				val = url::decode(piter->substring(pos + 1));
				pmap[ key ] = val;
			}
			else
			{
				key = piter->substring(0, pos);
				val = piter->substring(pos + 1);
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
blocxx::String
join(const blocxx::StringArray &params,
     const blocxx::String      &psep)
{
	blocxx::String                      str;
	blocxx::StringArray::const_iterator p( params.begin());

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
blocxx::String
join(const ca_mgm::url::ParamMap &pmap,
     const blocxx::String       &psep,
     const blocxx::String       &vsep,
     const blocxx::String       &safe)
{
	if( psep.empty() || vsep.empty())
	{
		BLOCXX_THROW(UrlNotSupportedException,
			__("Invalid parameter map join separator character.")
		);
	}

	blocxx::String join_safe;
	for(size_t i=0; i<safe.length(); i++)
	{
		if( psep.indexOf(safe[i]) == String::npos &&
		    vsep.indexOf(safe[i]) == String::npos)
		{
			join_safe.concat(safe[i]);
		}
	}
	blocxx::String           str;
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
parse_url_string(const blocxx::String &url)
{
	StringArray cap;
	try
	{
		blocxx::PosixRegEx reg(RX_SPLIT_URL);
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
                BLOCXX_THROW(UrlParsingException,
			__("Unable to parse main URL components.")
		);
	}
}


// -------------------------------------------------------------------
UrlAuthority
parse_url_authority(const blocxx::String &authority)
{
	StringArray cap;
	try
	{
		blocxx::PosixRegEx reg(RX_SPLIT_URL_AUTHORITY);
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
                BLOCXX_THROW(UrlParsingException,
			__("Unable to parse URL authority components.")
		);
	}
}


// -------------------------------------------------------------------
}      // End of url namespace
}      // End of LIMAL_NAMESPACE
// vim: set ts=8 sts=8 sw=8 ai noet:
