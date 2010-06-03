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

  File:       Logger.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   Logger.hpp
 * @brief  LiMaL logging utilities.
 *
 * The LiMaL extensions to the BloCxx logging framework.
 */
#ifndef LIMAL_LOGGER_HPP
#define LIMAL_LOGGER_HPP

#include  <blocxx/Array.hpp>
#include  <blocxx/String.hpp>
#include  <blocxx/StringStream.hpp>
#include  <blocxx/LogConfig.hpp>
#include  <blocxx/Logger.hpp>
#include  <blocxx/CommonFwd.hpp>
#include  <blocxx/LogAppender.hpp>
#include  <blocxx/AppenderLogger.hpp>
#include  <limal/ca-mgm/config.h>


/**
 * @brief Generic logging macro LIMAL_LOG
 *
 * This macro write a log message with the given level.
 *
 * @param logger        a Logger object
 * @param level         a log level
 * @param message       a log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_LOG(lg, DEBUG, "the log message");
 * LIMAL_LOG(lg, DEBUG, blocxx::Format("log message nr %1", 2));
 * @endcode
 */
#define LIMAL_LOG(logger, level, message)                         \
do                                                                \
{                                                                 \
	int err = errno;                                          \
	if( (logger).isEnabledFor(level))                         \
	{                                                         \
		(logger).logMessage((level), (message),           \
		                    __FILE__, __LINE__,           \
		         BLOCXX_LOGGER_PRETTY_FUNCTION);          \
	}                                                         \
	errno = err;                                              \
} while(0) // note the missing semicolon


/**
 * @brief Generic logging macro LIMAL_SLOG allowing
 * formating using a stream output operator <<.
 *
 * This macro write a log message with the given level.
 *
 * @param logger        a Logger object
 * @param level         a log level
 * @param message       a log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_SLOG(lg, DEBUG, "log message nr " << 3);
 * @endcode
 */
#define LIMAL_SLOG(logger, level, message)                        \
do                                                                \
{                                                                 \
	int err = errno;                                          \
	if( (logger).isEnabledFor(level))                         \
	{                                                         \
		blocxx::OStringStream _buf;                       \
		_buf << message;                                  \
		(logger).logMessage((level), _buf.toString(),     \
		                    __FILE__, __LINE__,           \
		         BLOCXX_LOGGER_PRETTY_FUNCTION);          \
	}                                                         \
	errno = err;                                              \
} while(0) // note the missing semicolon


/**
 * @brief Logging macro LIMAL_LOG_FATAL.
 *
 * This macro write a log message with the log level FATAL.
 *
 * @param logger a Logger object
 * @param logMessage the log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_LOG_FATAL(lg, "the log message");
 * LIMAL_SLOG_FATAL(lg, "log message " << 42);
 * @endcode
 */
#define LIMAL_LOG_FATAL(logger, logMessage) \
        LIMAL_LOG(logger, blocxx::E_FATAL_ERROR_LEVEL, logMessage)

#define LIMAL_SLOG_FATAL(logger, logMessage) \
        LIMAL_SLOG(logger, blocxx::E_FATAL_ERROR_LEVEL, logMessage)


/**
 * @brief Logging macro LIMAL_LOG_ERROR
 *
 * This macro write a log message with the log level ERROR
 *
 * @param logger a Logger object
 * @param logMessage the log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_LOG_ERROR(lg, "the log message");
 * LIMAL_SLOG_ERROR(lg, "log message " << 42);
 * @endcode
 */
#define LIMAL_LOG_ERROR(logger, logMessage) \
        LIMAL_LOG(logger, blocxx::E_ERROR_LEVEL, logMessage)

#define LIMAL_SLOG_ERROR(logger, logMessage) \
        LIMAL_SLOG(logger, blocxx::E_ERROR_LEVEL, logMessage)


/**
 * @brief Logging macro LIMAL_LOG_INFO
 *
 * This macro write a log message with the log level INFO
 *
 * @param logger a Logger object
 * @param logMessage the log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_LOG_INFO(lg, "the log message");
 * LIMAL_SLOG_INFO(lg, "log message " << 42);
 * @endcode
 */
#define LIMAL_LOG_INFO(logger, logMessage) \
        LIMAL_LOG(logger, blocxx::E_INFO_LEVEL, logMessage)

#define LIMAL_SLOG_INFO(logger, logMessage) \
        LIMAL_SLOG(logger, blocxx::E_INFO_LEVEL, logMessage)


/**
 * @brief Logging macro LIMAL_LOG_DEBUG
 *
 * This macro write a log message with the log level DEBUG
 *
 * @param logger a Logger object
 * @param logMessage the log message
 *
 * @code
 * ca_mgm::Logger lg("MyComponentName");
 * LIMAL_LOG_DEBUG(lg, "the log message");
 * LIMAL_SLOG_DEBUG(lg, "log message " << 42);
 * @endcode
 */
#define LIMAL_LOG_DEBUG(logger, logMessage) \
        LIMAL_LOG(logger, blocxx::E_DEBUG_LEVEL, logMessage)

#define LIMAL_SLOG_DEBUG(logger, logMessage) \
        LIMAL_SLOG(logger, blocxx::E_DEBUG_LEVEL, logMessage)


namespace LIMAL_NAMESPACE
{

/**
 * @brief LiMaL library logger class.
 *
 * The LiMaL logger class provides several static functions allowing to
 * create standard logger types (file, cerr, syslog), to set them as the
 * global/default or per thread logger in the blocxx library as well as
 * to retrieve them.
 * 
 * Each instance of the LiMaL logger contains a optional local component
 * name, that is passed with every log message to the current logger and
 * used instead of the default component name, that is set in the logger.
 *
 * This allows to use different component names at different places of
 * the application and/or library, e.g. each plugin logs messages using
 * own component name.
 *
 * The LiMaL logger instance can be used directly or with the LIMAL_LOG(),
 * LIMAL_SLOG() and derived macros.
 *
 * @par BloCxx Log Message Format
 *
 * BloCxx supports configuration of the log message format using printf()
 * style conversion specifiers.
 *
 * Available conversion specifiers:
 * @li @c %%c	The component (e.g. myapp)
 * @li @c %%d	The date. May be followed by a date format specifier enclosed
 *              between braces. Examples:
 *              @code
 *              "%d{%H:%M:%S}" 
 *              "%d{%d %b %Y %H:%M:%S}"
 *              @endcode
 *              If no date format specifier is given then ISO8601 format is
 *              assumed. For more information of the date format specifiers,
 *              lookup the documentation for the strftime() function found
 *              in the \<ctime\> header.
 *              The only addition is %%Q, which is the number of milliseconds.
 * @li @c %%F   The file name
 * @li @c %%l   The filename and line number. e.g. file.cpp(100)
 * @li @c %%L   The line number
 * @li @c %%M   The method name where the logging request was issued
 *              (only works on C++ compilers which support
 *               @c __PRETTY_FUNCTION__ or C99's @c __func__)
 * @li @c %%m   The message
 * @li @c %%e   The message as XML CDATA. This includes the @c "<![CDATA["
 *              and ending @c "]]>"
 * @li @c %%n   The platform dependent line separator character (\\n) or
 *              characters (\\r\\n)
 * @li @c %%P   The process id
 * @li @c %%p   Category, aka level, aka priority
 * @li @c %%r   The number of milliseconds elapsed since the start of the
 *              application until the creation of the logging event
 * @li @c %%t   The thread id
 * @li @c %%%%  The \% character.
 * @li @c \\n   The newline character
 * @li @c \\t   The tab character
 * @li @c \\r   The linefeed character
 * @li @c \\\\  The \\ character
 * @li @c \\x<hexDigits>  The character represented in hexadecimal.
 *
 * It is possible to change the minimum field width, the maximum field width
 * and justification. The optional format modifier is placed between the
 * percent sign and the conversion character.
 *
 * The first optional format modifier is the left justification flag which is
 * the minus (-) character. The optional minimum field width modifier follows.
 * It is an integer that represents the minimum number of characters to output.
 * If the data item requires fewer characters, it is padded with spaces on
 * either the left or the right, according to the justification flag. If the
 * data item is larger than the minimum field width, the field is expanded to
 * accommodate the data.
 *
 * The maximum field width modifier is designated by a period followed by a
 * decimal constant. If the data item is longer than the maximum field, then
 * the extra characters are removed from the beginning of the data item (by
 * default), or from the end if the left justification flag was specified.
 *
 * Examples:
 *
 *   Log4j TTCC layout:
 *   @code "%r [%t] %-5p %c - %m" @endcode
 *
 *   Similar to TTCC, but with some fixed size fields:
 *   @code "%-6r [%15.15t] %-5p %30.30c - %m" @endcode
 *
 *   The TTCC message format is defined in the
 *   @c blocxx::LogAppender::STR_TTCC_MESSAGE_FORMAT constant.
 */
class Logger
{
public:
	/**
	 * @brief Log level constants.
	 *
	 * Possible category names and their corresponding log levels are:
	 *
	 * @li @code "FATAL"    blocxx::E_FATAL_ERROR_LEVEL @endcode
	 * @li @code "ERROR"    blocxx::E_ERROR_LEVEL       @endcode
	 * @li @code "INFO"     blocxx::E_INFO_LEVEL        @endcode
	 * @li @code "DEBUG"    blocxx::E_DEBUG_LEVEL       @endcode
	 */
	typedef blocxx::ELogLevel       ELogLevel;

	/**
	 * @brief Create a new logger reference to a CerrLogger object.
	 *
	 * A application can use this function to create a logger reference
	 * pointing to a CerrLogger. The resulting reference object can be
	 * passed to the setDefaultLogger() or setThreadLogger() methods.
	 *
	 * @code
	 * blocxx::Array<blocxx::String> components;
	 * components.push_back("*");
	 *
	 * blocxx::Array<blocxx::String> categories;
	 * categories.push_back("*");
	 *
	 * blocxx::LoggerRef l = ca_mgm::Logger::createCerrLogger(
	 *                           "main", components, categories,
	 *                           "%r [%d] %p %c - %m"
	 *                       );
	 *
	 * ca_mgm::Logger::setDefaultLogger(l);
	 * @endcode
	 *
	 * @param component  The default component name (application name).
	 * @param components A filter list with component names that should
	 *                   be logged or "*" to log all components.
	 * @param categories A filter list with category names that should
	 *                   be logged or "*" for all categories. Category
	 *                   names are "FATAL", "ERROR", "INFO", "DEBUG".
	 * @param messageFormat A log message format string or empty string
	 *                      for default format defined by the logger.
	 * @return return A logger reference pointing to the CerrLogger.
	 */
	static blocxx::LoggerRef createCerrLogger(
	        const blocxx::String                &component,
		const blocxx::Array<blocxx::String> &components,
		const blocxx::Array<blocxx::String> &categories,
		const blocxx::String                &messageFormat
	);

	/**
	 * @brief Create a new logger reference to a SyslogLogger object.
	 *
	 * A application can use this function to create a logger reference
	 * pointing to a SyslogLogger. The resulting reference object can be
	 * passed to the setDefaultLogger() or setThreadLogger() methods.
	 *
	 * @code
	 * blocxx::Array<blocxx::String> components(1, "*");
	 * blocxx::Array<blocxx::String> categories(1, "*");
	 *
	 * blocxx::LoggerRef l = ca_mgm::Logger::createSyslogLogger(
	 *                           "main", components, categories,
	 *                           "%r [%d] %p %c - %m", "myApp", "user"
	 *                       );
	 *
	 * ca_mgm::Logger::setDefaultLogger(l);
	 * @endcode
	 *
	 * @param component  The default component name (application name).
	 * @param components A filter list with component names that should
	 *                   be logged or "*" to log all components.
	 * @param categories A filter list with category names that should
	 *                   be logged or "*" for all categories. Category
	 *                   names are "FATAL", "ERROR", "INFO", "DEBUG".
	 * @param messageFormat A log message format string or empty string
	 *                      for default format defined by the logger.
	 * @param identity   The syslog identity string.
	 * @param facility   The syslog facility to use ("user", "daemon", ...)
	 * @return return A logger reference pointing to the SyslogLogger.
	 */
	static blocxx::LoggerRef createSyslogLogger(
	        const blocxx::String                &component,
		const blocxx::Array<blocxx::String> &components,
		const blocxx::Array<blocxx::String> &categories,
		const blocxx::String                &messageFormat,
		const blocxx::String                &identity,
		const blocxx::String                &facility
	);


	/**
	 * @brief Create a new logger reference to a FileLogger object.
	 *
	 * A application can use this function to create a logger reference
	 * pointing to a FileLogger. The resulting reference object can be
	 * passed to the setDefaultLogger() or setThreadLogger() methods.
	 *
	 * @code
	 * blocxx::Array<blocxx::String> components(1, "*");
	 * blocxx::Array<blocxx::String> categories(1, "*");
	 *
	 * blocxx::LoggerRef l = ca_mgm::Logger::createFileLogger(
	 *                           "main", components, categories,
	 *                           "%r [%d] %p %c - %m",
	 *                           "/var/log/limal.log", 1024, 2
	 *                       );
	 *
	 * ca_mgm::Logger::setDefaultLogger(l);
	 * @endcode
	 *
	 * @param component  The default component name (application name).
	 * @param components A filter list with component names that should
	 *                   be logged or "*" to log all components.
	 * @param categories A filter list with category names that should
	 *                   be logged or "*" for all categories. Category
	 *                   names are "FATAL", "ERROR", "INFO", "DEBUG".
	 * @param messageFormat  A log message format string or empty string
	 *                       for default format defined by the logger.
	 * @param filename       The name of the log file.
	 * @param maxLogFileSize The maximal file size in kb. 0 disables
	 *                       automatic log file rotation.
	 * @param maxBackupIndex Maximal count of backup log files.
	 * @return return A logger reference pointing to the FileLogger.
	 */
	static blocxx::LoggerRef createFileLogger(
	        const blocxx::String                &component,
		const blocxx::Array<blocxx::String> &components,
		const blocxx::Array<blocxx::String> &categories,
		const blocxx::String                &messageFormat,
		const blocxx::String                &filename,
		blocxx::UInt64                      maxLogFileSize = 0,
		blocxx::UInt32                      maxBackupIndex = 0
	);

	/**
	 * @brief Create a new logger reference to a NullLogger object.
	 *
	 * A application can use this function to create a logger reference
	 * pointing to a NullLogger. The resulting reference object can be
	 * passed to the setDefaultLogger() or setThreadLogger() methods.
	 *
	 * @code
	 * blocxx::Array<blocxx::String> components(1, "*");
	 * blocxx::Array<blocxx::String> categories(1, "*");
	 *
	 * blocxx::LoggerRef l = ca_mgm::Logger::createNullLogger(
	 *                           "main", components, categories,
	 *                           "%r [%d] %p %c - %m"
	 *                       );
	 *
	 * ca_mgm::Logger::setDefaultLogger(l);
	 * @endcode
	 *
	 * @param component  The default component name (application name).
	 * @param components A filter list with component names that should
	 *                   be logged or "*" to log all components.
	 * @param categories A filter list with category names that should
	 *                   be logged or "*" for all categories. Category
	 *                   names are "FATAL", "ERROR", "INFO", "DEBUG".
	 * @param messageFormat A log message format string or empty string
	 *                      for default format defined by the logger.
	 * @return return A logger reference pointing to the NullLogger.
	 */
	static blocxx::LoggerRef createNullLogger(
	        const blocxx::String                &component,
		const blocxx::Array<blocxx::String> &components,
		const blocxx::Array<blocxx::String> &categories,
		const blocxx::String                &messageFormat
	);

	/**
	 * Create a new Logger instance.
	 *
	 * If no instance component is specified, then the default
	 * component of the registered logger is used instead.
	 *
	 * @param component      instance local component name
	 */
	Logger(const blocxx::String &component = "");


	/**
	 * Destroy a Logger instance
	 */
	~Logger();


	/**
	 * Set the default logger.
	 *
	 * @param ref	Reference to the new logger
	 * @returns	true if the logger was successfully set,
	 *              false if ref doesn't contain any logger.
	 */
	inline static bool
	setDefaultLogger(const blocxx::LoggerRef &ref)
	{
		return Logger::setDefaultFromLoggerRef(ref);
	}

	/**
	 * Set a per thread logger that overrides the default one.
	 *
	 * @param ref	Reference to the new logger
	 * @returns	true if the logger was successfully set,
	 *              false if ref doesn't contain any logger.
	 * @throws      AssertException if try to put the logger
	 *              into a thread local storage area failed.
	 */
	inline static bool
	setThreadLogger(const blocxx::LoggerRef &ref)
	{
		return Logger::setThreadFromLoggerRef(ref);
	}

	/**
	 * Returns a copy of default logger (LoggerRef).
	 * @returns	a LoggerRef to the default logger
	 */
	inline static blocxx::LoggerRef getDefaultLogger()
	{
		return Logger::getDefaultAsLoggerRef();
	}

	/**
	 * Get a copy of the per thread logger (LoggerRef)
	 * or if not set, the default one.
	 *
	 * @returns	a LoggerRef to the current logger
	 */
	inline static blocxx::LoggerRef getCurrentLogger()
	{
		return Logger::getCurrentAsLoggerRef();
	}

	/**
	 * log a message with the specified level inclusive
	 * the component name associated with the instance
	 * if not empty.
	 *
	 * @param level         a log level
	 * @param message       a log message
	 * @param filename      a file name (__FILE__)
	 * @param fileline      a line number (__LINE__)
	 * @param methodname    method name (__func__)
	 */
	void
	logMessage(ELogLevel             level,
	           const blocxx::String &message,
	           const char           *filename = 0,
	           int                   fileline = -1,
	           const char           *methodname = 0) const;


	/**
	 * log a message using the specified category (a log
	 * level name) inclusive component name associated
	 * with the instance if not empty.
	 *
	 * @param category      a log category
	 * @param message       a log message
	 * @param filename      a file name (__FILE__)
	 * @param fileline      a line number (__LINE__)
	 * @param methodname    method name (__func__)
	 */
	void
	logMessage(const blocxx::String &category,
	           const blocxx::String &message,
	           const char           *filename = 0,
	           int                   fileline = -1,
	           const char           *methodname = 0) const;


	/**
	 * Check if the logger is enabled for given level.
	 *
	 * @param level         a log level
	 * @return              true if enabled or false
	 */
	bool
	isEnabledFor(const ELogLevel level) const;


	/**
	 * Check if the logger is enabled for given category
	 * (named LogLevel, but not limited to).
	 *
	 * @param category      a log category
	 * @return              true if enabled or false
	 */
	bool
	isEnabledFor(const blocxx::String &category) const;


private:
	static bool setDefaultFromLoggerRef(const blocxx::LoggerRef &ref);
	static bool setThreadFromLoggerRef(const blocxx::LoggerRef &ref);
	static blocxx::LoggerRef getDefaultAsLoggerRef();
	static blocxx::LoggerRef getCurrentAsLoggerRef();

	blocxx::String m_component;

};


}      // LIMAL_NAMESPACE


#endif // LIMAL_LOGGER_HPP
/* vim: set ts=8 sts=8 sw=8 ai noet: */

