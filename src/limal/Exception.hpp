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
 *   BLOCXX_THROW_ERRNO_MSG(ca_mgm::SystemException,
 *                          "Can't do this and that");
 *
 *   const int MY_INVALID_EMAIL_ERROR_NUMBER = 42;
 *   BLOCXX_THROW_ERR(ca_mgm::ValueException,
 *                    "Argument is not a valid email",
 *                    MY_INVALID_EMAIL_ERROR_NUMBER);
 *
 *   BLOCXX_THROW(ca_mgm::SyntaxException,
 *                str::form("Syntax error in line %1", 42).c_str());
 *
 *   try
 *   {
 *       do_something();
 *   }
 *   catch(const blocxx::Exception &subex)
 *   {
 *       BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
 *                          "Bad things happened", subex);
 *   }
 * @endcode
 * See BloCxx documentation for more informations.
 */
#ifndef LIMAL_EXCEPTION_HPP
#define LIMAL_EXCEPTION_HPP

#include "blocxx/BLOCXX_config.h"
#include "blocxx/Exception.hpp"
#include "limal/ca-mgm/config.h"


namespace LIMAL_NAMESPACE
{

	/**
	 * @brief MemoryException class declaration
	 *
	 * A MemoryException happens during the allocation
	 * of memory. If you call <b>malloc</b> or <b>new</b>
	 * and the result is <b>0</b> you have to throw
	 * a MemoryException.
	 *
	 */
	BLOCXX_DECLARE_EXCEPTION(Memory);

	/**
	 * @brief RuntimeException class declaration
	 *
	 * A RuntimeException is thrown when the error results from
	 * a condition that the client could not have tested before
	 * calling the failing code.
	 *
	 */
	BLOCXX_DECLARE_EXCEPTION(Runtime);

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
	BLOCXX_DECLARE_EXCEPTION(Overflow);

	/**
	 * @brief SyntaxException class declaration
	 *
	 * A SyntaxException is thrown if a parser fails to
	 * parse a configuration file because of syntax errors
	 * in the configuration files or similar problems.
	 *
	 */
	BLOCXX_DECLARE_EXCEPTION(Syntax);


	/**
	 * @brief ValueException class declaration.
	 *
	 * A ValueException is thrown in case of failed parameter checks.
	 * E.g. a string should be an email address, but it is not.
	 *
	 */
	BLOCXX_DECLARE_EXCEPTION(Value);

	/**
     	 * @brief SystemException class declaration
	 *
	 * A system error is thrown in case of reached system limits.
	 *
	 */
	BLOCXX_DECLARE_EXCEPTION(System);

}      // End of LIMAL_NAMESPACE

#endif /* LIMAL_EXCEPTION_HPP */
