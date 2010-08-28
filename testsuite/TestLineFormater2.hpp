#ifndef LIMAL_TEST_LINE_FORMATER2_HPP
#define LIMAL_TEST_LINE_FORMATER2_HPP

#include <iosfwd>
#include <string>
#include <ca-mgm/LogControl.hpp>

///////////////////////////////////////////////////////////////////
//namespace ca_mgm
//{ /////////////////////////////////////////////////////////////////

    struct TestLineFormater2 : public ca_mgm::LogControl::LineFormater
    {
      virtual std::string format( const std::string &      group_r,
                                  ca_mgm::logger::LogLevel level_r,
                                  const char *             ,
                                  const char *             ,
                                  int                      ,
                                  const std::string &      message_r )
      {
        if(level_r == ca_mgm::logger::E_ERROR)
        {
          return ca_mgm::str::form( "%-5s %s - %s",
                                    ca_mgm::logger::logLevelToString( level_r).c_str(),
                                    group_r.c_str(), "not log openssl errors for testing");
        }
        else
        {
          return ca_mgm::str::form( "%-5s %s - %s",
                                    ca_mgm::logger::logLevelToString( level_r).c_str(),
                                    group_r.c_str(), message_r.c_str());
        }
      }
      virtual ~TestLineFormater2() {}
    };


  /////////////////////////////////////////////////////////////////
//} // namespace ca_mgm
///////////////////////////////////////////////////////////////////
#endif // LIMAL_TEST_LINE_FORMATER_HPP
