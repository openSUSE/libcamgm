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

  File:       ByteBuffer.cpp

  Maintainer: Michael Calmer

/-*/

#include <ca-mgm/ByteBuffer.hpp>

#include <ca-mgm/String.hpp>
#include <ca-mgm/Exception.hpp>

#include <cstring>

#include "Utils.hpp"


// -----------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{


// -----------------------------------------------------------------------
// --- Inner ByteBufferImpl class ----------------------------------------
// -----------------------------------------------------------------------
class ByteBufferImpl

{
public:

	ByteBufferImpl()
	    : m_len(0)
	    , m_buf(NULL)
	{
	}

	ByteBufferImpl(const char *str)
	    : m_len(::strlen(str))
	    , m_buf(new char[m_len + 1])
	{
	    ::memmove(m_buf, str, m_len);
	    m_buf[m_len] = '\0';
	}

	ByteBufferImpl(const char *ptr, size_t len)
	    : m_len(len)
	    , m_buf(new char[m_len + 1])
	{
	    ::memmove(m_buf, ptr, m_len);
	    m_buf[m_len] = '\0';
	}

	ByteBufferImpl(const ByteBufferImpl &buf)
	    : m_len(buf.m_len)
	    , m_buf(new char[m_len + 1])
	{
	    ::memmove(m_buf, buf.m_buf, m_len);
	    m_buf[m_len] = '\0';
	}

	~ByteBufferImpl()
	{
	    delete [] m_buf;
	    m_buf = NULL;
	    m_len = 0;
	}

	ByteBufferImpl &
	operator=(const ByteBufferImpl &buf)
	{
	    if(this == &buf)
	        return *this;

	    char* tmpbuf = new char[buf.m_len + 1];
	    ::memmove(tmpbuf, buf.m_buf, buf.m_len);

	    delete [] m_buf;
	    m_len = buf.m_len;
	    m_buf = tmpbuf;
	    m_buf[m_len] = '\0';

	    return *this;
	}

	void append(const char *ptr, size_t len)
	{
	    if(m_len && len)
	    {
		size_t newlen = m_len + len;
		char*  tmpbuf = new char[newlen + 1];

		::memcpy(tmpbuf,  m_buf, m_len);
		::memcpy(tmpbuf + m_len, ptr, len);
		delete [] m_buf;
		m_len = newlen;
		m_buf = tmpbuf;
		m_buf[m_len] = '\0';
	    }
	    else if(len)
	    {
		m_len = len;
		m_buf = new char[m_len + 1];
		::memcpy(m_buf, ptr, m_len);
		m_buf[m_len] = '\0';
	    }
	}

	void
	clear()
	{
      m_len = 0;
      m_buf = NULL;
    }

	size_t
	size() const
	{
	    return m_len;
	}

	char*
	data() const
	{
	    return m_buf;
	}

	ByteBufferImpl* clone() const
	{
	    return new ByteBufferImpl(*this);
	}

private:

	size_t m_len;
	char*  m_buf;
};



// -------------------------------------------------------------------
// --- ByteBuffer class ----------------------------------------------
// -------------------------------------------------------------------
ByteBuffer::ByteBuffer()
    : m_impl(new ByteBufferImpl())
{}


// -------------------------------------------------------------------
ByteBuffer::ByteBuffer(const char *str)
    : m_impl(new ByteBufferImpl(str))
{}


// -------------------------------------------------------------------
ByteBuffer::ByteBuffer(const char *ptr, size_t len)
    : m_impl(new ByteBufferImpl(ptr, len))
{}


// -------------------------------------------------------------------
ByteBuffer::ByteBuffer(const ByteBuffer& buf)
    : m_impl(buf.m_impl)
{
}


// -------------------------------------------------------------------
ByteBuffer::~ByteBuffer()
{
}


// -------------------------------------------------------------------
ByteBuffer &
ByteBuffer::operator=(const ByteBuffer& buf)
{
    if(this == &buf)
	return *this;

    m_impl = buf.m_impl;
    return *this;
}


// -------------------------------------------------------------------
void
ByteBuffer::clear()
{
    m_impl->clear();
}


// -------------------------------------------------------------------
bool
ByteBuffer::empty() const
{
    return (size() == 0) ? true : false;
}


// -------------------------------------------------------------------
size_t
ByteBuffer::size() const
{
    return (m_impl) ? m_impl->size() : 0;
}


// -------------------------------------------------------------------
const char *
ByteBuffer::data() const
{
    return (m_impl) ? m_impl->data() : "";
}


// -------------------------------------------------------------------
char
ByteBuffer::at(size_t pos) const
{
    if(pos < size())
    {
        return (m_impl)? m_impl->data()[pos] : '\0';
    }

    LOGIT_ERROR("ByteBuffer index out of bounds: size="
                << size() << ", pos=" << pos);
    CA_MGM_THROW(ca_mgm::OutOfBoundsException, str::form(
                 __("ByteBuffer index out of bounds: size=%1, pos=%2."),
                 size(), pos).c_str());
}


// -------------------------------------------------------------------
void
ByteBuffer::append(const char *ptr, size_t len)
{
    if(ptr != NULL)
    {
      if(m_impl)
      {
        m_impl->append(ptr, len);
      }
      else
      {
        CA_MGM_THROW(ca_mgm::RuntimeException, __("ByteBuffer not initialized"));
      }
    }
}


// -------------------------------------------------------------------
void
ByteBuffer::append(char c)
{
  if(m_impl)
  {
    m_impl->append(&c, 1);
  }
  else
  {
    CA_MGM_THROW(ca_mgm::RuntimeException, __("ByteBuffer not initialized"));
  }
}


// -------------------------------------------------------------------
const char&
ByteBuffer::operator[](size_t pos) const
{
    if(pos < size())
    {
        return *(m_impl->data() + pos);
    }

    LOGIT_ERROR("ByteBuffer index out of bounds: size="
                << size() << ", pos=" << pos);
    CA_MGM_THROW(ca_mgm::OutOfBoundsException, str::form(
                 __("ByteBuffer index out of bounds: size=%1, pos=%2."),
                 size(), pos).c_str());
}


// -------------------------------------------------------------------
char&
ByteBuffer::operator[](size_t pos)
{
    if(pos < size())
    {
        return m_impl->data()[pos];
    }

    LOGIT_ERROR("ByteBuffer index out of bounds: size="
                << size() << ", pos=" << pos);
    CA_MGM_THROW(ca_mgm::OutOfBoundsException, str::form(
                 __("ByteBuffer index out of bounds: size=%1, pos=%2."),
                 size(), pos).c_str());
}


// -------------------------------------------------------------------
ByteBuffer&
ByteBuffer::operator+=(const ByteBuffer& buf)
{
    append(buf.data(), buf.size());
    return *this;
}


// -------------------------------------------------------------------
// --- ByteBuffer class friends --------------------------------------
// -------------------------------------------------------------------
// friend
bool
operator==(const ByteBuffer &l, const ByteBuffer &r)
{
    const char* lhs = "";
    const char* rhs = "";

    if(l.size() == r.size())
    {
        if(!l.empty())
            lhs = l.data();

        if(!r.empty())
            rhs = r.data();

        int i = ::memcmp(lhs, rhs, l.size());

        return (i == 0) ? true : false;
    }

    return false;
}


// -------------------------------------------------------------------
// friend
bool
operator!=(const ByteBuffer &l, const ByteBuffer &r)
{
    return !(l == r);
}


// -------------------------------------------------------------------
// friend
bool
operator<(const ByteBuffer &l, const ByteBuffer &r)
{
    const char* lhs = "";
    const char* rhs = "";

    int i = 0;

    if(l.size() == r.size())
    {
        if(!l.empty())
            lhs = l.data();

        if(!r.empty())
            rhs = r.data();

        i = ::memcmp(lhs, rhs, l.size());
    }
    else if(l.size() < r.size())
    {
        i = -1;
    }
    else
    {
        i = 1;
    }

    return (i < 0) ? true : false;
}


// -------------------------------------------------------------------
// friend
bool
operator>(const ByteBuffer &l, const ByteBuffer &r)
{
    return (!(l < r) || !(l == r));
}


// -------------------------------------------------------------------
// friend
bool
operator<=(const ByteBuffer &l, const ByteBuffer &r)
{
    return ( (l < r) ||  (l == r));
}


// -------------------------------------------------------------------
// friend
bool
operator>=(const ByteBuffer& l, const ByteBuffer& r)
{
    return (!(l < r));
}


// -------------------------------------------------------------------
// friend
ByteBuffer
operator+(const ByteBuffer &b1, const ByteBuffer &b2)
{
    ByteBuffer ret(b1);
    ret.append(b2.data(), b2.size());
    return ret;
}


// -------------------------------------------------------------------
// friend
/*
 * For debugging
 */
std::ostream &
operator<<(std::ostream &out, const ByteBuffer &buf)
{
  if(buf.size() > 0)
  {
    const char    *x = buf.data();
    std::string s;
    for(size_t i = 0; i < buf.size(); ++i)
    {
      s = str::form("0x%02x ", x[i]);
      out << s;
      if( ((i + 1) % 16) == 0)
        out << std::endl;
    }
  }
  else
  {
    out << "No data";
  }

  return out;
}


// -------------------------------------------------------------------
}      // End Of LIMAL_NAMESPACE

