#include <ca-mgm/Exception.hpp>

namespace
{
char* dupString(const char* str)
{
  if (!str)
  {
    return 0;
  }
  char* rv = new (std::nothrow) char[strlen(str)+1];
  if (!rv)
  {
    return 0;
  }
  strcpy(rv, str);
  return rv;
}
static void freeBuf(char** ptr)
{
        delete [] *ptr;
        *ptr = NULL;
}
}

namespace CA_MGM_NAMESPACE
{

Exception::Exception(const char* file, int line, const char* msg, int errorCode, const Exception* subException)
        : std::exception()
        , m_file(dupString(file))
        , m_line(line)
        , m_msg(dupString(msg))
        , m_errorCode(errorCode)
{
  if( subException != NULL )
  {
    try
    {
      m_msg = dupString(str::form("%s\n\t%s", m_msg, subException->getFullMessage().c_str()).c_str());
    }
    catch (...)
    {}
  }
}

 Exception::Exception( const Exception& e )
    : std::exception(e)
    , m_file(dupString(e.m_file))
    , m_line(e.m_line)
    , m_msg(dupString(e.m_msg))
    , m_errorCode(e.m_errorCode)
{}

Exception::~Exception() throw()
{
  try
  {
    freeBuf(&m_file);
    freeBuf(&m_msg);
  }
  catch (...)
  {
    // don't let exceptions escape
  }
}

Exception&
Exception::operator=(const Exception& rhs)
{
  if(this == &rhs) return *this;

  m_file = rhs.m_file;
  m_line = rhs.m_line;
  m_msg  = rhs.m_msg;
  m_errorCode = rhs.m_errorCode;

  return *this;
}
//////////////////////////////////////////////////////////////////////////////
const char*
Exception::type() const
{
        return "Exception";
}

//////////////////////////////////////////////////////////////////////////////
int
Exception::getLine() const
{
        return m_line;
}

//////////////////////////////////////////////////////////////////////////////
const char*
Exception::getMessage() const
{
        return (m_msg != NULL) ? m_msg : "";
}
//////////////////////////////////////////////////////////////////////////////
std::string
Exception::getFullMessage() const
{
    try
    {
      return str::form("%s: %s %s: %s%s",
                       (getFile() == NULL)?"[no file]":getFile(),
                       (getLine() == 0)?"[no line]":str::numstring(getLine()).c_str(),
                       type(),
                       (getErrorCode() != 0)?(str::numstring(getErrorCode())+": ").c_str():" ",
                       (getMessage() == NULL)?"[no message]":getMessage()
                      );
    }
    catch (...)
    {}
    return "";
}
//////////////////////////////////////////////////////////////////////////////
const char*
Exception::getFile() const
{
        return (m_file != NULL) ? m_file : "";
}
//////////////////////////////////////////////////////////////////////////////
std::ostream&
operator<<(std::ostream& os, const Exception& e)
{
        if (*e.getFile() == '\0')
        {
                os << "[no file]: ";
        }
        else
        {
                os << e.getFile() << ": ";
        }

        if (e.getLine() == 0)
        {
                os << "[no line] ";
        }
        else
        {
                os << e.getLine() << ' ';
        }

        os << e.type() << ": ";

        if (e.getErrorCode() != 0)
        {
                os << e.getErrorCode() << ": ";
        }

        if (*e.getMessage() == '\0')
        {
                os << "[no message]";
        }
        else
        {
                os << e.getMessage();
        }
        return os;
}
//////////////////////////////////////////////////////////////////////////////
const char*
Exception::what() const throw()
{
        return getMessage();
}
//////////////////////////////////////////////////////////////////////////////
int
Exception::getErrorCode() const
{
        return m_errorCode;
}


  CA_MGM_DEFINE_EXCEPTION(Memory);
  CA_MGM_DEFINE_EXCEPTION(Runtime);
  CA_MGM_DEFINE_EXCEPTION(Overflow);
  CA_MGM_DEFINE_EXCEPTION(Syntax);
  CA_MGM_DEFINE_EXCEPTION(Value);
  CA_MGM_DEFINE_EXCEPTION(System);
  CA_MGM_DEFINE_EXCEPTION(OutOfBounds);

}
