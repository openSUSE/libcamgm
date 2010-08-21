%module CaMgm

/*
  for limal libraries use %import _not_ %include
  %include happens in limal (core) library
*/

%{
#include <limal/ByteBuffer.hpp>
#include <limal/LogControl.hpp>
%}

namespace ca_mgm
{
    class ByteBuffer
    {
    public:
        ByteBuffer();
        ByteBuffer(const char *str);
        ByteBuffer(const char *ptr, size_t len);
        ByteBuffer(const ByteBuffer &buf);
        ~ByteBuffer();
        void        clear();
        bool        empty() const;
        size_t      size() const;
        const char* data() const;
        char        at(size_t pos) const;
        void        append(const char *ptr, size_t len);
        void        append(char c);
    };

    namespace logger
    {
      enum LogLevel {
        E_FATAL = 1,
        E_ERROR = 2,
        E_WARN  = 3,
        E_INFO  = 4,
        E_DEBUG = 5
      };
    }

    class LogControl
    {
    public:
      /** Singleton access. */
      static LogControl instance();
      void logNothing();
      void logToStdErr();
      void setLogLevel( logger::LogLevel level_r );
    private:
      LogControl();
    };
}
