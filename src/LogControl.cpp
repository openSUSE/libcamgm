/** \file	LogControl.cc
 *
*/
#include <iostream>
#include <fstream>
#include <string>

#include <ca-mgm/Logger.hpp>
#include <ca-mgm/LogControl.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/Date.hpp>
#include <ca-mgm/PathInfo.hpp>

using std::endl;

///////////////////////////////////////////////////////////////////
namespace ca_mgm
{ /////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////
  namespace log
  { /////////////////////////////////////////////////////////////////

    StdoutLineWriter::StdoutLineWriter()
      : StreamLineWriter( std::cout )
    {}

    StderrLineWriter::StderrLineWriter()
      : StreamLineWriter( std::cerr )
    {}

    FileLineWriter::FileLineWriter( const path::PathName & file_r, mode_t mode_r )
    {
      if ( file_r == path::PathName("-") )
      {
        _str = &std::cerr;
      }
      else
      {
        // set unbuffered write
        std::ofstream * fstr = 0;
        _outs.reset( (fstr = new std::ofstream( file_r.toString().c_str(), std::ios_base::app )) );
        fstr->rdbuf()->pubsetbuf(0,0);
        _str = &(*fstr);
        if ( mode_r )
        {
          // not filesystem::chmod, as filesystem:: functions log,
          // and this FileWriter is not yet in place.
          ::chmod( file_r.toString().c_str(), mode_r );
        }
      }
    }

    /////////////////////////////////////////////////////////////////
  } // namespace log
  ///////////////////////////////////////////////////////////////////


    ///////////////////////////////////////////////////////////////////
    // LineFormater
    ///////////////////////////////////////////////////////////////////
    std::string LogControl::LineFormater::format( const std::string & group_r,
                                                  logger::LogLevel    level_r,
                                                  const char *        file_r,
                                                  const char *        func_r,
                                                  int                 line_r,
                                                  const std::string & message_r )
    {
      static char hostname[1024];
      static char nohostname[] = "unknown";
      std::string now( Date::now().form( "%Y-%m-%d %H:%M:%S" ) );
      return str::form( "%s <%d> %s(%d) [%s] %s(%s):%d %s",
                        now.c_str(), level_r,
                        ( gethostname( hostname, 1024 ) ? nohostname : hostname ),
                        getpid(),
                        group_r.c_str(),
                        file_r, func_r, line_r,
                        message_r.c_str() );
    }

    ///////////////////////////////////////////////////////////////////
    namespace logger
    { /////////////////////////////////////////////////////////////////

      inline void putStream( const std::string & group_r, LogLevel level_r,
                             const char * file_r, const char * func_r, int line_r,
                             const std::string & buffer_r );

      ///////////////////////////////////////////////////////////////////
      //
      //	CLASS NAME : Loglinebuf
      //
      class Loglinebuf : public std::streambuf {

      public:
        /** */
        Loglinebuf( const std::string & group_r, LogLevel level_r )
        : _group( group_r )
        , _level( level_r )
        , _file( "" )
        , _func( "" )
        , _line( -1 )
        {}
        /** */
        ~Loglinebuf()
        {
          if ( !_buffer.empty() )
            writeout( "\n", 1 );
        }

        /** */
        void tagSet( const char * fil_r, const char * fnc_r, int lne_r )
        {
          _file = fil_r;
          _func = fnc_r;
          _line = lne_r;
        }

      private:
        /** */
        virtual std::streamsize xsputn( const char * s, std::streamsize n )
        { return writeout( s, n ); }
        /** */
        virtual int overflow( int ch = EOF )
        {
          if ( ch != EOF )
            {
              char tmp = ch;
              writeout( &tmp, 1 );
            }
          return 0;
        }
        /** */
        virtual int writeout( const char* s, std::streamsize n )
        {
          if ( s && n )
            {
              const char * c = s;
              for ( int i = 0; i < n; ++i, ++c )
                {
                  if ( *c == '\n' ) {
                    _buffer += std::string( s, c-s );
                    logger::putStream( _group, _level, _file, _func, _line, _buffer );
                    _buffer = std::string();
                    s = c+1;
                  }
                }
              if ( s < c )
                {
                  _buffer += std::string( s, c-s );
                }
            }
          return n;
        }

      private:
        std::string  _group;
        LogLevel     _level;
        const char * _file;
        const char * _func;
        int          _line;
        std::string  _buffer;
      };

      ///////////////////////////////////////////////////////////////////

      ///////////////////////////////////////////////////////////////////
      //
      //	CLASS NAME : Loglinestream
      //
      class Loglinestream {

      public:
        /** */
        Loglinestream( const std::string & group_r, LogLevel level_r )
        : _mybuf( group_r, level_r )
        , _mystream( &_mybuf )
        {}
        /** */
        ~Loglinestream()
        { _mystream.flush(); }

      public:
        /** */
        std::ostream & getStream( const char * fil_r, const char * fnc_r, int lne_r )
        {
          _mybuf.tagSet( fil_r, fnc_r, lne_r );
          return _mystream;
        }

      private:
        Loglinebuf   _mybuf;
        std::ostream _mystream;
      };
      ///////////////////////////////////////////////////////////////////

      ///////////////////////////////////////////////////////////////////
      //
      //	CLASS NAME : LogControlImpl
      //
      /** LogControl implementation (Singleton).
       *
       * \note There is a slight difference in using the _lineFormater and _lineWriter!
       * \li \c _lineFormater must not be NULL (create default LogControl::LineFormater)
       * \li \c _lineWriter is NULL if no logging is performed, this way we can pass
       *        _no_stream as logstream to the application, and avoid unnecessary formating
       *        of logliles, which would then be discarded when passed to some dummy
       *        LineWriter.
      */
      struct LogControlImpl
      {
      public:
        bool isEnabledFor( LogLevel level_r )
        { return (level_r <= _level); }

        void setLogLevel( LogLevel level_r )
        { _level = level_r; }

        /** NULL _lineWriter indicates no loggin. */
        void setLineWriter( const shared_ptr<LogControl::LineWriter> & writer_r )
        { _lineWriter = writer_r; }

        shared_ptr<LogControl::LineWriter> getLineWriter() const
        { return _lineWriter; }

        /** Assert \a _lineFormater is not NULL. */
        void setLineFormater( const shared_ptr<LogControl::LineFormater> & format_r )
        {
          if ( format_r )
            _lineFormater = format_r;
          else
            _lineFormater.reset( new LogControl::LineFormater );
        }

        void logfile( const path::PathName & logfile_r, mode_t mode_r = 0640 )
        {
          if ( logfile_r.empty() )
            setLineWriter( shared_ptr<LogControl::LineWriter>() );
          else if ( logfile_r == path::PathName( "-" ) )
            setLineWriter( shared_ptr<LogControl::LineWriter>(new log::StderrLineWriter) );
          else
            setLineWriter( shared_ptr<LogControl::LineWriter>(new log::FileLineWriter(logfile_r, mode_r)) );
        }

      private:
        std::ostream _no_stream;
        int          _level;

        shared_ptr<LogControl::LineFormater> _lineFormater;
        shared_ptr<LogControl::LineWriter>   _lineWriter;

      public:
        /** Provide the log stream to write (logger interface) */
        std::ostream & getStream( const std::string & group_r,
                                  LogLevel            level_r,
                                  const char *        file_r,
                                  const char *        func_r,
                                  const int           line_r )
        {
          if ( ! _lineWriter )
            return _no_stream;
          if ( level_r > _level )
            return _no_stream;

          if ( !_streamtable[group_r][level_r] )
            {
              _streamtable[group_r][level_r].reset( new Loglinestream( group_r, level_r ) );
            }
          return _streamtable[group_r][level_r]->getStream( file_r, func_r, line_r );
        }

        /** Format and write out a logline from Loglinebuf. */
        void putStream( const std::string & group_r,
                        LogLevel            level_r,
                        const char *        file_r,
                        const char *        func_r,
                        int                 line_r,
                        const std::string & message_r )
        {
          if ( _lineWriter )
            _lineWriter->writeOut( _lineFormater->format( group_r, level_r,
                                                          file_r, func_r, line_r,
                                                          message_r ) );
        }

      private:
        typedef shared_ptr<Loglinestream>        StreamPtr;
        typedef std::map<LogLevel,StreamPtr>     StreamSet;
        typedef std::map<std::string,StreamSet>  StreamTable;
        /** one streambuffer per group and level */
        StreamTable _streamtable;

      private:
        /** Singleton ctor.
         * No logging per default, unless enabled via $CAMGM_LOGFILE.
        */
        LogControlImpl()
        : _no_stream( NULL )
        , _level( E_INFO )
        , _lineFormater( new LogControl::LineFormater )
        {
          if ( getenv("CAMGM_LOGFILE") )
            logfile( getenv("CAMGM_LOGFILE") );
        }

      public:
        /** The LogControlImpl singleton
         * \note As most dtors log, it is inportant that the
         * LogControlImpl instance is the last static variable
         * destructed. At least destucted after all statics
         * which log from their dtor.
        */
        static LogControlImpl instance;
      };
      ///////////////////////////////////////////////////////////////////

      // 'THE' LogControlImpl singleton
      LogControlImpl LogControlImpl::instance;

      ///////////////////////////////////////////////////////////////////

      /** \relates LogControlImpl Stream output */
      inline std::ostream & operator<<( std::ostream & str, const LogControlImpl & obj )
      {
        return str << "LogControlImpl";
      }

      ///////////////////////////////////////////////////////////////////
      //
      // Access from logger::
      //
      ///////////////////////////////////////////////////////////////////

      std::ostream & getStream( const char * group_r,
                                LogLevel     level_r,
                                const char * file_r,
                                const char * func_r,
                                const int    line_r )
      {
        return LogControlImpl::instance.getStream( group_r,
                                                   level_r,
                                                   file_r,
                                                   func_r,
                                                   line_r );
      }

      /** That's what Loglinebuf calls.  */
      inline void putStream( const std::string & group_r, LogLevel level_r,
                             const char * file_r, const char * func_r, int line_r,
                             const std::string & buffer_r )
      {
        LogControlImpl::instance.putStream( group_r, level_r,
                                            file_r, func_r, line_r,
                                            buffer_r );
      }

      bool isEnabledFor( logger::LogLevel level_r )
      { return LogControlImpl::instance.isEnabledFor( level_r ); }

      void setLogLevel( logger::LogLevel level_r )
      { LogControlImpl::instance.setLogLevel( level_r); }

      std::string logLevelToString( LogLevel level_r )
      {
        switch (level_r)
        {
          case E_FATAL:
            return "FATAL";
            break;
          case E_ERROR:
            return "ERROR";
            break;
          case E_WARN:
            return "WARN";
            break;
          case E_INFO:
            return "INFO";
            break;
          case E_DEBUG:
            return "DEBUG";
            break;
        }
        return "UNKNOWN";
      }

      /////////////////////////////////////////////////////////////////
    } // namespace logger
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //
    //	CLASS NAME : LogControl
    //  Forward to LogControlImpl singleton.
    //
    ///////////////////////////////////////////////////////////////////

    using logger::LogControlImpl;

    void LogControl::logfile( const path::PathName & logfile_r )
    { LogControlImpl::instance.logfile( logfile_r ); }

    void LogControl::logfile( const path::PathName & logfile_r, mode_t mode_r )
    { LogControlImpl::instance.logfile( logfile_r, mode_r ); }

    shared_ptr<LogControl::LineWriter> LogControl::getLineWriter() const
    { return LogControlImpl::instance.getLineWriter(); }

    void LogControl::setLineWriter( const shared_ptr<LineWriter> & writer_r )
    { LogControlImpl::instance.setLineWriter( writer_r ); }

    void LogControl::setLineFormater( const shared_ptr<LineFormater> & formater_r )
    { LogControlImpl::instance.setLineFormater( formater_r ); }

    void LogControl::setShortLineFormater()
    {
        boost::shared_ptr<LogControl::LineFormater> formater(new ShortLineFormater());
        LogControl::setLineFormater(formater);
    }

    void LogControl::logNothing()
    { LogControlImpl::instance.setLineWriter( shared_ptr<LineWriter>() ); }

    void LogControl::logToStdErr()
    { LogControlImpl::instance.setLineWriter( shared_ptr<LineWriter>( new log::StderrLineWriter ) ); }

    bool LogControl::isEnabledFor( logger::LogLevel level_r )
    { return LogControlImpl::instance.isEnabledFor( level_r ); }

    void LogControl::setLogLevel( logger::LogLevel level_r )
    { LogControlImpl::instance.setLogLevel( level_r); }

    /******************************************************************
     **
     **	FUNCTION NAME : operator<<
     **	FUNCTION TYPE : std::ostream &
    */
    std::ostream & operator<<( std::ostream & str, const LogControl & obj )
    {
      return str << LogControlImpl::instance;
    }

  /////////////////////////////////////////////////////////////////
} // namespace ca_mgm
///////////////////////////////////////////////////////////////////
