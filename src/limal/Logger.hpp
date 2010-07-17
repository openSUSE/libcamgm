/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file zypp/base/Logger.h
 *
*/
#ifndef LIMAL_LOGGER_H
#define LIMAL_LOGGER_H

#include <iosfwd>
#include <cstring>
#include <limal/String.hpp>

/** \defgroup LIMAL_LOGGER_MACROS LIMAL_LOGGER_MACROS
 *  Convenience macros for logging.
 *
 * The macros finaly call @ref getStream, providing appropriate arguments,
 * to return the log stream.
 *
 * @code
 * _DBG("foo") << ....
 * @endcode
 * Logs a debug message for group @a "foo".
 *
 * @code
 * #undef LIMAL_LOGGER_LOGGROUP
 * #define LIMAL_LOGGER_LOGGROUP "foo"
 *
 * DBG << ....
 * @endcode
 * Defines group @a "foo" as default for log messages and logs a
 * debug message.
 */
/*@{*/

#ifndef LIMAL_LOGGER_LOGGROUP
/** Default log group is ca_mgm. */
#define LIMAL_LOGGER_LOGGROUP "ca_mgm"
#endif

#define DBG _DBG( LIMAL_LOGGER_LOGGROUP )
#define INF _INF( LIMAL_LOGGER_LOGGROUP )
#define WAR _WAR( LIMAL_LOGGER_LOGGROUP )
#define ERR _ERR( LIMAL_LOGGER_LOGGROUP )
#define FAT _FAT( LIMAL_LOGGER_LOGGROUP )

#define _DBG(GROUP) LIMAL_LOGGER_LOG( GROUP, ca_mgm::logger::E_DEBUG )
#define _INF(GROUP) LIMAL_LOGGER_LOG( GROUP, ca_mgm::logger::E_INFO )
#define _WAR(GROUP) LIMAL_LOGGER_LOG( GROUP, ca_mgm::logger::E_WARN )
#define _ERR(GROUP) LIMAL_LOGGER_LOG( GROUP, ca_mgm::logger::E_ERROR )
#define _FAT(GROUP) LIMAL_LOGGER_LOG( GROUP, ca_mgm::logger::E_FATAL )

#define _BASEFILE ( *__FILE__ == '/' ? strrchr( __FILE__, '/' ) + 1 : __FILE__ )

/** Actual call to @ref getStream. */
#define LIMAL_LOGGER_LOG(GROUP,LEVEL) \
        ca_mgm::logger::getStream( GROUP, LEVEL, _BASEFILE, __FUNCTION__, __LINE__ )

/*@}*/

///////////////////////////////////////////////////////////////////
namespace ca_mgm
{ /////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    namespace logger
    { /////////////////////////////////////////////////////////////////

      /** Definition of log levels.
       *
       * @see getStream
      */
      enum LogLevel {
        E_FATAL = 1,
        E_ERROR = 2,
        E_WARN  = 3,
        E_INFO  = 4,
        E_DEBUG = 5
      };
      extern std::string logLevelToString( LogLevel level_r );

      /** Return a log stream to write on.
       *
       * The returned log stream is determined by @a group_r and
       * @a level_r. The remaining arguments @a file_r, @a func_r
       * and @a line_r are expected to denote the location in the
       * source code that issued the message.
       *
       * @note You won't call @ref getStream directly, but use the
       * @ref LIMAL_LOGGER_MACROS.
      */
      extern std::ostream & getStream( const char * group_r,
                                       LogLevel     level_r,
                                       const char * file_r,
                                       const char * func_r,
                                       const int    line_r );
      extern bool isEnabledFor( LogLevel level_r );

      extern void setLogLevel( LogLevel level_r );

      /////////////////////////////////////////////////////////////////
    } // namespace logger
    ///////////////////////////////////////////////////////////////////

  /////////////////////////////////////////////////////////////////
} // namespace ca_mgm
///////////////////////////////////////////////////////////////////
#endif // LIMAL_LOGGER_H
