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

  File:       Exception.hpp

  Author:     Michael Calmer
  Maintainer: Michael Calmer

/-*/
/**
 * @file   Exception.hpp
 * @brief  Common LiMaL exceptions.
 *
 * This header file declares several common exception types.
 *
 * BloCxx provides several macros helping to throw exceptions:
 * @code
 *   #include <limal/Exception.hpp>
 *
 *
 *   CA_MGM_THROW_ERRNO_MSG(ca_mgm::SystemException,
 *                          "Can't do this and that");
 *
 *   const int MY_INVALID_EMAIL_ERROR_NUMBER = 42;
 *   CA_MGM_THROW_ERR(ca_mgm::ValueException,
 *                    "Argument is not a valid email",
 *                    MY_INVALID_EMAIL_ERROR_NUMBER);
 *
 *   CA_MGM_THROW(ca_mgm::SyntaxException,
 *                str::form("Syntax error in line %1", 42).c_str());
 *
 *   try
 *   {
 *       do_something();
 *   }
 *   catch(const ca_mgm::Exception &subex)
 *   {
 *       CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
 *                          "Bad things happened", subex);
 *   }
 * @endcode
 * See BloCxx documentation for more informations.
 */
#ifndef LIMAL_EXCEPTION_HPP
#define LIMAL_EXCEPTION_HPP

#include "limal/ca-mgm/config.h"
#include <limal/String.hpp>
#include <string.h>

namespace LIMAL_NAMESPACE
{

  class Exception : public std::exception
  {
    friend std::ostream & operator<<( std::ostream & str, const Exception & obj );

    protected:
      Exception(const char* file, int line, const char* msg,
                int errorCode, const Exception *otherException = 0);

    public:
      Exception(const Exception& e);
      Exception& operator= (const Exception& rhs);
      virtual ~Exception() throw();

      /**
       * Returns a string representing the concrete type.  e.g. "SocketException".  Will not return 0.
       * This function will not throw.  Derived class implementations must not throw.
       */
      virtual const char* type() const;
      /**
       * Returns the message.  May return 0.
       * This function will not throw.  Derived class implementations must not throw.
       */
      virtual const char* getMessage() const;
      /**
       * Returns the full message.
       * This function will not throw.  Derived class implementations must not throw.
       */
      virtual std::string getFullMessage() const;

      /**
       * Returns the file.  May return 0.
       */
      const char* getFile() const;
      int getLine() const;

      /**
       * Returns the error code representing the error which occurred.
       * Code are unique only in the scope of the derived exception class.
       * May return UNKNONWN_ERROR_CODE if the error is unavailable.
       */
      int getErrorCode() const;

      /**
       * Returns getMessage()
       */
      virtual const char* what() const throw();

    private:
      char* m_file;
      int m_line;
      char* m_msg;
      int m_errorCode;
  };

namespace ExceptionDetail
{
  unsigned const BUFSZ = 1024;

  template <typename exType>
  struct Errno
  {
    static exType simple(char const * file, int line, int errnum)
    {
      return exType(file, line, ::strerror(errnum), errnum);
    }

    template <typename Mtype>
    static exType format(char const * file, int line,
                         Mtype const & msg, int errnum)
    {
      return format(file, line, msg.c_str(), errnum);
    }

    static exType format(char const * file, int line,
                         char const * msg, int errnum)
    {
      return exType(file, line, str::form("%s: %d(%s)", msg, errnum, ::strerror(errnum)).c_str(), errnum);
    }
  }; // struct Errno
}

/**
 * Declare a new exception class named \<NAME\>Exception that derives from \<BASE\>.
 * This macro is typically used in a header file.
 *
 * @param NAME The name of the new class (Exception will be postfixed)
 * @param BASE The base class.
 */
#define CA_MGM_DECLARE_EXCEPTION2(NAME, BASE) \
class NAME##Exception : public BASE \
{ \
public: \
        NAME##Exception(const char* file, int line, const char* msg, int errorCode = 0, const ca_mgm::Exception* otherException = 0); \
        virtual ~NAME##Exception() throw(); \
        virtual const char* type() const; \
};

/**
 * Declare a new exception class named \<NAME\>Exception that derives from Exception
 * This macro is typically used in a header file.
 *
 * @param NAME The name of the new class (Exception will be postfixed)
 */
#define CA_MGM_DECLARE_EXCEPTION(NAME) CA_MGM_DECLARE_EXCEPTION2(NAME, ca_mgm::Exception)

/**
 * Define a new exception class named \<NAME\>Exception that derives from \<BASE\>.
 * The new class will use UNKNOWN_SUBCLASS_ID for the subclass id.
 * This macro is typically used in a cpp file.
 *
 * @param NAME The name of the new class (Exception will be postfixed)
 * @param BASE The base class.
 */
#define CA_MGM_DEFINE_EXCEPTION2(NAME, BASE) \
NAME##Exception::NAME##Exception(const char* file, int line, const char* msg, int errorCode, const ::ca_mgm::Exception* otherException) \
        : BASE(file, line, msg, errorCode, otherException) {} \
NAME##Exception::~NAME##Exception() throw() { } \
const char* NAME##Exception::type() const { return #NAME "Exception"; }\

/**
 * Define a new exception class named \<NAME\>Exception that derives from Exception.
 * The new class will use UNKNOWN_SUBCLASS_ID for the subclass id.
 * Use this macro for internal implementation exceptions that don't have an id.
 * This macro is typically used in a cpp file.
 *
 * @param NAME The name of the new class (Exception will be postfixed)
 */
#define CA_MGM_DEFINE_EXCEPTION(NAME) CA_MGM_DEFINE_EXCEPTION2(NAME, ca_mgm::Exception)

/**
 * Throw an exception using __FILE__ and __LINE__.  If applicable,
 * CA_MGM_THROW_ERR should be used instead of this macro.
 *
 * @param exType The type of the exception
 * @param msg The exception message.  A string that will be copied.
 */
#define CA_MGM_THROW(exType, msg) throw exType(__FILE__, __LINE__, (msg))

/**
 * Throw an exception using __FILE__ and __LINE__.
 * @param exType The type of the exception
 * @param msg The exception message.  A string that will be copied.
 * @param subex A sub-exception. A pointer to it will be passed to the
 *   exception constructor, which should clone() it.
 */
#define CA_MGM_THROW_SUBEX(exType, msg, subex) \
throw exType(__FILE__, __LINE__, (msg), -1, &(subex))

/**
 * Throw an exception using __FILE__ and __LINE__.
 * @param exType The type of the exception
 * @param msg The exception message.  A string that will be copied.
 * @param err The error code.
 */
#define CA_MGM_THROW_ERR(exType, msg, err) \
throw exType(__FILE__, __LINE__, (msg), (err))
/**
 * Throw an exception using __FILE__, __LINE__, errno and strerror(errno)
 * @param exType The type of the exception; ctor must take file, line,
 *               message, and error code.
 */
#define CA_MGM_THROW_ERRNO(exType) CA_MGM_THROW_ERRNO1(exType, errno)

/**
 * Throw an exception using __FILE__, __LINE__, errnum and strerror(errnum)
 * @param exType The type of the exception; ctor must take file, line,
 *               message, and error code.
 * @param errnum The errno value.
 */
#define CA_MGM_THROW_ERRNO1(exType, errnum) \
throw ::ca_mgm::ExceptionDetail::Errno< exType >::simple(__FILE__, __LINE__, (errnum))

/**
 * Throw an exception using __FILE__, __LINE__, errno and strerror(errno)
 * @param exType The type of the exception; ctor must take file, line,
 *               message, and error code.
 * @param msg The exception message to use.
 */
#define CA_MGM_THROW_ERRNO_MSG(exType, msg) \
CA_MGM_THROW_ERRNO_MSG1(exType, (msg), errno)

/**
 * Throw an exception using __FILE__, __LINE__, errnum and strerror(errnum)
 * @param exType The type of the exception; ctor must take file, line,
 *               message, and error code.
 * @param msg The exception message to use.
 * @param errnum The errno value.
 */
#define CA_MGM_THROW_ERRNO_MSG1(exType, msg, errnum) \
throw ::ca_mgm::ExceptionDetail::Errno< exType >:: \
      format(__FILE__, __LINE__, (msg), (errnum))


	/**
	 * @brief MemoryException class declaration
	 *
	 * A MemoryException happens during the allocation
	 * of memory. If you call <b>malloc</b> or <b>new</b>
	 * and the result is <b>0</b> you have to throw
	 * a MemoryException.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(Memory);

	/**
	 * @brief RuntimeException class declaration
	 *
	 * A RuntimeException is thrown when the error results from
	 * a condition that the client could not have tested before
	 * calling the failing code.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(Runtime);

	/**
	 * @brief OverflowException class declaration
	 *
	 * An OverflowException is thrown when an arithmetic
	 * overflow is encountered. An other case is during
	 * an cast from e.g. UInt64 to uint where the UInt64
	 * value is larger then the size of the destination
	 * type.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(Overflow);

	/**
	 * @brief SyntaxException class declaration
	 *
	 * A SyntaxException is thrown if a parser fails to
	 * parse a configuration file because of syntax errors
	 * in the configuration files or similar problems.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(Syntax);


	/**
	 * @brief ValueException class declaration.
	 *
	 * A ValueException is thrown in case of failed parameter checks.
	 * E.g. a string should be an email address, but it is not.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(Value);

	/**
     	 * @brief SystemException class declaration
	 *
	 * A system error is thrown in case of reached system limits.
	 *
	 */
	CA_MGM_DECLARE_EXCEPTION(System);

	CA_MGM_DECLARE_EXCEPTION(OutOfBounds);

}      // End of LIMAL_NAMESPACE

#endif /* LIMAL_EXCEPTION_HPP */
