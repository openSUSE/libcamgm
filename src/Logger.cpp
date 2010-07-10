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

  File:       Logger.cpp

  Maintainer: Marius Tomaschewski

/-*/
#include <limal/Logger.hpp>
#include <limal/Exception.hpp>
#include <limal/String.hpp>
#include <blocxx/NullAppender.hpp>
#include <blocxx/CerrAppender.hpp>
#include <blocxx/FileAppender.hpp>
#include <blocxx/SyslogAppender.hpp>
#include <blocxx/LogMessage.hpp>


#include "Utils.hpp"


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{

using namespace blocxx;


// -------------------------------------------------------------------
#if BLOCXX_LIBRARY_VERSION >= 5
namespace
{
	class LoggerWrapper: public blocxx::Logger
	{
	public:
		virtual
		~LoggerWrapper()
		{}

		LoggerWrapper()
			: blocxx::Logger()
		{}
		LoggerWrapper(const blocxx::Logger &logger)
			: blocxx::Logger(logger)
		{}

		bool setAsDefaultLogAppender()
		{
			return LogAppender::setDefaultLogAppender(
				blocxx::Logger::m_appender
			);
		}
		bool setAsThreadLogAppender()
		{
			return LogAppender::setThreadLogAppender(
				blocxx::Logger::m_appender
			);
		}
	};
}
#endif


// -------------------------------------------------------------------
Logger::Logger(const String &component)
	: m_component(component)
{
}


// -------------------------------------------------------------------
Logger::~Logger()
{
}


// -------------------------------------------------------------------
void
Logger::logMessage(ELogLevel     level,
                   const String &message,
                   const char   *filename,
                   int           fileline,
                   const char   *methodname) const
{
	String category;
	switch( level)
	{
	case blocxx::E_ALL_LEVEL:
		category = blocxx::Logger::STR_ALL_CATEGORY;
	break;

	case blocxx::E_FATAL_ERROR_LEVEL:
		category = blocxx::Logger::STR_FATAL_CATEGORY;
	break;

	case blocxx::E_ERROR_LEVEL:
		category = blocxx::Logger::STR_ERROR_CATEGORY;
	break;

	case blocxx::E_INFO_LEVEL:
		category = blocxx::Logger::STR_INFO_CATEGORY;
	break;

	case blocxx::E_DEBUG_LEVEL:
		category = blocxx::Logger::STR_DEBUG_CATEGORY;
	break;

	case blocxx::E_NONE_LEVEL:
	default:
		category = blocxx::Logger::STR_NONE_CATEGORY;
	break;
	}

	return logMessage(
		category, message, filename, fileline, methodname
	);
}


// -------------------------------------------------------------------
void
Logger::logMessage(const String &category,
                   const String &message,
                   const char   *filename,
                   int           fileline,
                   const char   *methodname) const
{
#if BLOCXX_LIBRARY_VERSION >= 5
	if( m_component.empty())
	{
		blocxx::LogAppender::getCurrentLogAppender()->logMessage(
			blocxx::LogMessage(
				blocxx::Logger::STR_DEFAULT_COMPONENT,
				category, message,
				filename, fileline, methodname
			)
		);
	}
	else
	{
		blocxx::LogAppender::getCurrentLogAppender()->logMessage(
			blocxx::LogMessage(
				m_component,
				category, message,
				filename, fileline, methodname
			)
		);
	}
#else
	if( m_component.empty())
	{
		blocxx::Logger::getCurrentLogger()->logMessage(
			category, message,
			filename, fileline, methodname
		);
	}
	else
	{
		blocxx::Logger::getCurrentLogger()->logMessage(
			m_component,
			category, message,
			filename, fileline, methodname
		);
	}
#endif
}


// -------------------------------------------------------------------
bool
Logger::isEnabledFor(const ELogLevel level) const
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return LogAppender::getCurrentLogAppender()->getLogLevel() >= level;
#else
	return Logger::getCurrentLogger()->levelIsEnabled(level);
#endif
}


// -------------------------------------------------------------------
bool
Logger::isEnabledFor(const String &category) const
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return LogAppender::getCurrentLogAppender()->categoryIsEnabled(category);
#else
	return Logger::getCurrentLogger()->categoryIsEnabled(category);
#endif
}


// -------------------------------------------------------------------
LoggerRef
Logger::createCerrLogger(const String      &component,
                         const StringArray &components,
                         const StringArray &categories,
                         const String      &messageFormat)
{
	String defname( !component.empty() ? component :
	                 blocxx::Logger::STR_DEFAULT_COMPONENT);
	String mformat( !messageFormat.empty() ? messageFormat :
	                 CerrAppender::STR_DEFAULT_MESSAGE_PATTERN);

	LogAppenderRef appRef(new CerrAppender(
		components,categories, mformat
	));

#if BLOCXX_LIBRARY_VERSION >= 5
	LoggerRef      logRef(new blocxx::Logger(
		defname, appRef
	));
#else
	LoggerRef      logRef(new AppenderLogger(
		defname, E_ALL_LEVEL, appRef
	));
#endif
	return logRef;
}


// -------------------------------------------------------------------
LoggerRef
Logger::createSyslogLogger(const String      &component,
                           const StringArray &components,
                           const StringArray &categories,
                           const String      &messageFormat,
                           const String      &identity,
                           const String      &facility)
{
	String defname( !component.empty() ? component :
	                 blocxx::Logger::STR_DEFAULT_COMPONENT);
	String mformat( !messageFormat.empty() ? messageFormat :
	                 SyslogAppender::STR_DEFAULT_MESSAGE_PATTERN);
	String log_tag( identity.empty() || identity.isSpaces() ? defname :
                        identity);

	LogAppenderRef appRef(new SyslogAppender(
                components,
                categories,
		mformat, log_tag, facility
	));

#if BLOCXX_LIBRARY_VERSION >= 5
	LoggerRef      logRef(new blocxx::Logger(
		defname, appRef
	));
#else
	LoggerRef      logRef(new AppenderLogger(
		defname, E_ALL_LEVEL, appRef
	));
#endif
	return logRef;
}


// -------------------------------------------------------------------
LoggerRef
Logger::createNullLogger(const String      &component,
                         const StringArray &components,
                         const StringArray &categories,
                         const String      &messageFormat)
{
	String defname( !component.empty() ? component :
	                 blocxx::Logger::STR_DEFAULT_COMPONENT);
	String mformat( !messageFormat.empty() ? messageFormat :
	                 NullAppender::STR_DEFAULT_MESSAGE_PATTERN);

	LogAppenderRef appRef(new NullAppender(
                components,
                categories,
		mformat
	));

#if BLOCXX_LIBRARY_VERSION >= 5
	LoggerRef      logRef(new blocxx::Logger(
		defname, appRef
	));
#else
	LoggerRef      logRef(new AppenderLogger(
		defname, E_ALL_LEVEL, appRef
	));
#endif
	return logRef;
}


// -------------------------------------------------------------------
LoggerRef
Logger::createFileLogger(const String      &component,
                         const StringArray &components,
                         const StringArray &categories,
                         const String      &messageFormat,
                         const String      &filename,
                         UInt64            maxLogFileSize,
                         UInt32            maxBackupIndex)
{
	String defname( !component.empty() ? component :
	                 blocxx::Logger::STR_DEFAULT_COMPONENT);
	String mformat( !messageFormat.empty() ? messageFormat :
	                 FileAppender::STR_DEFAULT_MESSAGE_PATTERN);

	if( maxLogFileSize >= (UInt64(-1) / UInt64(1024)))
	{
		CA_MGM_THROW(ca_mgm::OverflowException,
			__("The specified maximum log file size is too big.")
		);
	}
	if( filename.empty())
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			__("The log file path should be set.")
		);
	}
	if( !filename.startsWith(BLOCXX_FILENAME_SEPARATOR))
	{
		CA_MGM_THROW(ca_mgm::ValueException,
			str::form(__("The specified log file name '%s' "
			          "is not absolute"),
			       filename.c_str()).c_str()
		);
	}

	LogAppenderRef appRef(new FileAppender(
                components,
                categories,
		filename.c_str(),
		mformat, maxLogFileSize, maxBackupIndex
	));

#if BLOCXX_LIBRARY_VERSION >= 5
	LoggerRef      logRef(new blocxx::Logger(
		defname, appRef
	));
#else
	LoggerRef      logRef(new AppenderLogger(
		defname, E_ALL_LEVEL, appRef
	));
#endif
	return logRef;
}


// -------------------------------------------------------------------
//static
bool Logger::setDefaultFromLoggerRef(const blocxx::LoggerRef &ref)
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return LoggerWrapper(*ref).setAsDefaultLogAppender();
#else
	return blocxx::Logger::setDefaultLogger(ref);
#endif
}


// -------------------------------------------------------------------
//static
bool Logger::setThreadFromLoggerRef(const blocxx::LoggerRef &ref)
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return LoggerWrapper(*ref).setAsThreadLogAppender();
#else
	return blocxx::Logger::setThreadLogger(ref);
#endif
}


// -------------------------------------------------------------------
//static
blocxx::LoggerRef
Logger::getDefaultAsLoggerRef()
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return blocxx::LoggerRef(new blocxx::Logger(
		blocxx::Logger::STR_DEFAULT_COMPONENT,
		blocxx::LogAppender::getDefaultLogAppender()
	));
#else
	return blocxx::Logger::getDefaultLogger();
#endif
}


// -------------------------------------------------------------------
//static
blocxx::LoggerRef
Logger::getCurrentAsLoggerRef()
{
#if BLOCXX_LIBRARY_VERSION >= 5
	return blocxx::LoggerRef(new blocxx::Logger(
		blocxx::Logger::STR_DEFAULT_COMPONENT,
		blocxx::LogAppender::getCurrentLogAppender()
	));
#else
	return blocxx::Logger::getCurrentLogger();
#endif
}


// -------------------------------------------------------------------
}      // LIMAL_NAMESPACE
/* vim: set ts=8 sts=8 sw=8 ai noet: */
