/*******************************************************************************
* Copyright (C) 2005 Novell, Inc. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  - Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
*  - Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
*  - Neither the name of Quest Software, Inc., Novell, Inc., nor the names of its
*    contributors may be used to endorse or promote products derived from this
*    software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL Quest Software, Inc., Novell, Inc., OR THE
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
* OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/
/**
 * @author Marius Tomaschewski
 */

#include <ca-mgm/config.h>
#include <ca-mgm/PerlRegEx.hpp>
#include <ca-mgm/Exception.hpp>

#include <climits> // for INT_MAX


namespace ca_mgm
{


// -------------------------------------------------------------------
static std::string
substitute_caps(const PerlRegEx::MatchArray &sub,
                const std::string &str, const std::string &rep)
{
	static const char *cap_refs[] = {
		NULL,  "\\1", "\\2", "\\3", "\\4",
		"\\5", "\\6", "\\7", "\\8", "\\9", NULL
	};

	std::string res( rep);
	size_t pos;

	for(size_t i=1; cap_refs[i] != NULL; i++)
	{
		std::string cap;
		if( i < sub.size() && sub[i].rm_so >= 0 && sub[i].rm_eo >= 0)
		{
			cap = str.substr(sub[i].rm_so, sub[i].rm_eo
			                             - sub[i].rm_so);
		}

		pos = res.find_first_of(cap_refs[i]);
		while( pos != std::string::npos)
		{
			size_t quotes = 0;
			size_t at = pos;

			while( at > 0 && res.at(--at) == '\\')
				quotes++;

			if( quotes % 2)
			{
				quotes = (quotes + 1) / 2;

				res = res.erase(pos - quotes, quotes);

				pos = res.find_first_of(cap_refs[i],
				                        pos + 2 - quotes);
			}
			else
			{
				quotes = quotes / 2;

				res = res.substr(0, pos - quotes) +
				      cap +
				      res.substr(pos + 2);

				pos = res.find_first_of(cap_refs[i],
				                        pos + cap.length() - quotes);
			}
		}
	}
	return res;
}


// -------------------------------------------------------------------
static inline std::string
getError(const int errcode)
{
	const char *ptr;
	switch(errcode)
	{
		case 0:
			ptr = "match vector to small";
		break;

		case PCRE_ERROR_NOMATCH:
			ptr = "match failed";
		break;

		case PCRE_ERROR_NULL:
			ptr = "invalid argument";
		break;

		case PCRE_ERROR_BADOPTION:
			ptr = "unrecognized option";
		break;

		case PCRE_ERROR_BADMAGIC:
			ptr = "invalid magic number";
		break;

		case PCRE_ERROR_UNKNOWN_NODE:
			ptr = "unknown item in the compiled pattern";
		break;

		case PCRE_ERROR_NOMEMORY:
			ptr = "failed to allocate memory";
		break;

		case PCRE_ERROR_NOSUBSTRING:
			// .*_substring.* functions only
			ptr = "failed to retrieve substring";
		break;

		case PCRE_ERROR_MATCHLIMIT:
			// match_limit in pcre_extra struct
			ptr = "recursion or backtracking limit reached";
		break;

		case PCRE_ERROR_CALLOUT:
			// reserved for pcrecallout functions
			ptr = "callout failure";
		break;

		case PCRE_ERROR_BADUTF8:
			ptr = "invalid UTF-8 byte sequence found";
		break;

		case PCRE_ERROR_BADUTF8_OFFSET:
			ptr = "not a UTF-8 character at specified index";
		break;

#ifdef PCRE_ERROR_PARTIAL
		case PCRE_ERROR_PARTIAL:
			ptr = "partial match";
		break;
#endif

#ifdef PCRE_ERROR_BADPARTIAL
		case PCRE_ERROR_BADPARTIAL:
			ptr = "pattern item not supported for partial matching";
		break;
#endif

#ifdef PCRE_ERROR_INTERNAL
		case PCRE_ERROR_INTERNAL:
			ptr = "unexpected internal error occurred";
		break;
#endif

#ifdef PCRE_ERROR_BADCOUNT
		case PCRE_ERROR_BADCOUNT:
			ptr = "invalid (negative) match vector count";
		break;
#endif

		default:
			ptr = "unknown error code";
		break;
	}
	return std::string(ptr);
}

// -------------------------------------------------------------------
PerlRegEx::PerlRegEx()
	: m_pcre(NULL)
	, m_flags(0)
	, m_ecode(0)
{
}


// -------------------------------------------------------------------
PerlRegEx::PerlRegEx(const std::string &regex, int cflags)
	: m_pcre(NULL)
	, m_flags(0)
	, m_ecode(0)
{
	if( !compile(regex, cflags))
	{
		CA_MGM_THROW_ERR(ca_mgm::ValueException,
			errorString().c_str(), m_ecode);
	}
}


// -------------------------------------------------------------------
PerlRegEx::PerlRegEx(const PerlRegEx &ref)
	: m_pcre(NULL)
	, m_flags(ref.m_flags)
	, m_ecode(0)
	, m_rxstr(ref.m_rxstr)
{
	if( ref.m_pcre != NULL && !compile(ref.m_rxstr, ref.m_flags))
	{
		CA_MGM_THROW_ERR(ca_mgm::ValueException,
			errorString().c_str(), m_ecode);
	}
}

// -------------------------------------------------------------------
PerlRegEx::~PerlRegEx()
{
	if( m_pcre)
	{
		free(m_pcre);
		m_pcre = NULL;
	}
}


// -------------------------------------------------------------------
PerlRegEx &
PerlRegEx::operator = (const PerlRegEx &ref)
{
	if( ref.m_pcre == NULL)
	{
		m_ecode = 0;
		m_error.erase();
		m_flags = ref.m_flags;
		m_rxstr = ref.m_rxstr;
		if( m_pcre != NULL)
		{
			free(m_pcre);
			m_pcre = NULL;
		}
	}
	else if( !compile(ref.m_rxstr, ref.m_flags))
	{
		CA_MGM_THROW_ERR(ca_mgm::ValueException,
			errorString().c_str(), m_ecode);
	}
	return *this;
}


// -------------------------------------------------------------------
bool
PerlRegEx::compile(const std::string &regex, int cflags)
{
	if( m_pcre)
	{
		free(m_pcre);
		m_pcre = NULL;
	}

	const char *errptr = NULL;

	m_ecode = 0;
	m_pcre  = ::pcre_compile(regex.c_str(), cflags,
	                         &errptr, &m_ecode, NULL);
	if( m_pcre == NULL)
	{
		m_error = std::string(errptr ? errptr : "");
		m_rxstr.erase();
		m_flags = 0;
		return false;
	}
	else
	{
		m_error.erase();
		m_rxstr = regex;
		m_flags = cflags;
		return true;
	}
}


// -------------------------------------------------------------------
int
PerlRegEx::errorCode()
{
	return m_ecode;
}


// -------------------------------------------------------------------
std::string
PerlRegEx::errorString() const
{
	return m_error;
}


// -------------------------------------------------------------------
std::string
PerlRegEx::patternString() const
{
	return m_rxstr;
}


// -------------------------------------------------------------------
int
PerlRegEx::compileFlags() const
{
	return m_flags;
}


// -------------------------------------------------------------------
bool
PerlRegEx::isCompiled() const
{
	return (m_pcre != NULL);
}


// -------------------------------------------------------------------
bool
PerlRegEx::execute(MatchArray &sub, const std::string &str,
               size_t index, size_t count, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}
	if( count >= size_t(INT_MAX / 3))
	{
		CA_MGM_THROW(ca_mgm::SystemException,
			"Match count limit exceeded");
	}

	if( index > str.length())
	{
		CA_MGM_THROW(ca_mgm::OverflowException,
			str::form("String index out of bounds ("
			          "length = %d, index = %d).",
			          str.length(), index
			).c_str());
	}

	if( count == 0)
	{
		int cnt = 0;
		int ret = ::pcre_fullinfo(m_pcre, NULL,
		                          PCRE_INFO_CAPTURECOUNT, &cnt);
		if( ret)
		{
			m_error = getError(m_ecode);
			return false;
		}
		count = cnt > 0 ? cnt + 1 : 1;
	}
	int vsub[count * 3];

	sub.clear();
	m_ecode = ::pcre_exec(m_pcre, NULL, str.c_str(), str.length(),
	                      index, eflags, vsub, count * 3);
	//
	// pcre_exec returns 0 if vector too small, negative value
	// on errors or the number of matches (number of int pairs)
	//
	if( m_ecode > 0)
	{
		sub.resize(count); // as specified by user
		for(size_t i = 0, n = 0; i < count; i++, n += 2)
		{
			match_t  m = { vsub[n], vsub[n+1] };

			// if user wants more than detected
			if( i >= (size_t)m_ecode)
				m.rm_so = m.rm_eo = -1;

			sub[i] = m;
		}
		m_error.erase();
		return true;
	}
	else
	{
		m_error = getError(m_ecode);
		return false;
	}
}


// -------------------------------------------------------------------
bool
PerlRegEx::execute(MatchVector &sub, const std::string &str,
               size_t index, size_t count, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}
	if( count >= size_t(INT_MAX / 3))
	{
		CA_MGM_THROW(ca_mgm::SystemException,
			"Match count limit exceeded");
	}

	if( index > str.length())
	{
		CA_MGM_THROW(ca_mgm::OverflowException,
			str::form("String index out of bounds ("
			          "length = %d, index = %d)",
			          str.length(), index
			).c_str());
	}

	if( count == 0)
	{
		int cnt = 0;
		int ret = ::pcre_fullinfo(m_pcre, NULL,
		                          PCRE_INFO_CAPTURECOUNT, &cnt);
		if( ret)
		{
			m_error = getError(m_ecode);
			return false;
		}
		count = cnt > 0 ? cnt + 1 : 1;
	}
	int vsub[count * 3];

	sub.clear();
	m_ecode = ::pcre_exec(m_pcre, NULL, str.c_str(), str.length(),
	                      index, eflags, vsub, count * 3);
	//
	// pcre_exec returns 0 if vector too small, negative value
	// on errors or the number of matches (number of int pairs)
	//
	if( m_ecode > 0)
	{
		count   *= 2;
		m_ecode *= 2;
		sub.resize(count); // as specified by user
		for(size_t i = 0; i < count; i++)
		{
			// if user wants more than detected
			if( i >= (size_t)m_ecode)
				vsub[i] = -1;

			sub[i] = vsub[i];
		}
		return true;
	}
	else
	{
		m_error = getError(m_ecode);
		return false;
	}
}


// -------------------------------------------------------------------
std::vector<std::string>
PerlRegEx::capture(const std::string &str, size_t index, size_t count, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}

	MatchArray  rsub;
	std::vector<std::string> ssub;

	bool match = execute(rsub, str, index, count, eflags);
	if( match)
	{
		if( rsub.empty())
		{
			CA_MGM_THROW(ca_mgm::ValueException,
				"Non-capturing regular expression");
		}

		MatchArray::const_iterator i=rsub.begin();
		for( ; i != rsub.end(); ++i)
		{
			if( i->rm_so >= 0 && i->rm_eo >= 0)
			{
				ssub.push_back(str.substr(i->rm_so,
				               i->rm_eo - i->rm_so));
			}
			else
			{
				ssub.push_back(std::string(""));
			}
		}
	}
	else if(m_ecode != PCRE_ERROR_NOMATCH)
	{
		CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
			errorString().c_str(), m_ecode);
	}
	return ssub;
}


// -------------------------------------------------------------------
std::string
PerlRegEx::replace(const std::string &str, const std::string &rep,
                   bool global, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}

	MatchArray  rsub;
	bool        match;
	size_t      off = 0;
	std::string      out = str;

	do
	{
		match = execute(rsub, out, off, 0, eflags);
		if( match)
		{
			if( rsub.empty()      ||
			    rsub[0].rm_so < 0 ||
			    rsub[0].rm_eo < 0)
			{
				// only if empty (missused as guard).
				CA_MGM_THROW(ca_mgm::ValueException,
					"Non-capturing regular expression");
			}

			std::string res = substitute_caps(rsub, out, rep);

			out = out.substr(0, rsub[0].rm_so) +
			      res + out.substr(rsub[0].rm_eo);

			off = rsub[0].rm_so + res.length();
		}
		else if(m_ecode == PCRE_ERROR_NOMATCH)
		{
			m_ecode = 0;
			m_error.erase();
		}
		else
		{
			CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
				errorString().c_str(), m_ecode);
		}
	} while(global && match && out.length() > off);

	return out;
}


// -------------------------------------------------------------------
std::vector<std::string>
PerlRegEx::split(const std::string &str, bool empty, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}

	MatchArray  rsub;
	std::vector<std::string> ssub;
	bool        match;
	size_t      off = 0;
	size_t      len = str.length();

	do
	{
		match = execute(rsub, str, off, 0, eflags);
		if( match)
		{
			if( rsub.empty()      ||
			    rsub[0].rm_so < 0 ||
			    rsub[0].rm_eo < 0)
			{
				CA_MGM_THROW(ca_mgm::ValueException,
					"Non-capturing regular expression");
			}

			if( empty || ((size_t)rsub[0].rm_so > off))
			{
				ssub.push_back(str.substr(off,
				                   rsub[0].rm_so - off));
			}
			off = rsub[0].rm_eo;
		}
		else if(m_ecode == PCRE_ERROR_NOMATCH)
		{
			std::string tmp = str.substr(off);
			if( empty || !tmp.empty())
			{
				ssub.push_back(tmp);
			}
			m_ecode = 0;
			m_error.erase();
		}
		else
		{
			CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
				errorString().c_str(), m_ecode);
		}
	} while(match && len > off);

	return ssub;
}


// -------------------------------------------------------------------
std::vector<std::string>
PerlRegEx::grep(const std::vector<std::string> &src, int eflags)
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}

	m_ecode = 0;
	m_error.erase();

	std::vector<std::string> out;
	if( !src.empty())
	{
		std::vector<std::string>::const_iterator i=src.begin();
		for( ; i != src.end(); ++i)
		{
			int ret = ::pcre_exec(m_pcre, NULL, i->c_str(),
			          i->length(), 0, eflags, NULL, 0);
			if( ret >= 0)
			{
				out.push_back(*i);
			}
			else if( ret != PCRE_ERROR_NOMATCH)
			{
				m_ecode = ret;
				m_error = getError(m_ecode);
				CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
					errorString().c_str(), m_ecode);
			}
		}
	}
	return out;
}


// -------------------------------------------------------------------
bool
PerlRegEx::match(const std::string &str, size_t index, int eflags) const
{
	if( m_pcre == NULL)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			"Regular expression is not compiled");
	}

	if( index > str.length())
	{
		CA_MGM_THROW(ca_mgm::OverflowException,
			str::form("String index out of bounds."
			          "length = %d, index = %d",
			          str.length(), index
			).c_str());
	}

	m_ecode = ::pcre_exec(m_pcre, NULL, str.c_str(),
	          str.length(), 0, eflags, NULL, 0);
	if( m_ecode >= 0)
	{
		m_error.erase();
		return true;
	}
	else if( m_ecode == PCRE_ERROR_NOMATCH)
	{
		m_error = getError(m_ecode);
		return false;
	}
	else
	{
		m_error = getError(m_ecode);
		CA_MGM_THROW_ERR(ca_mgm::RuntimeException,
			errorString().c_str(), m_ecode);
	}
}


// -------------------------------------------------------------------
} // namespace BLOCXX_NAMESPACE

/* vim: set ts=8 sts=8 sw=8 ai noet: */

