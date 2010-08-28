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

  File:       Date.cpp

  Author: Michael Andres

/-*/
#include <iostream>

#include <ca-mgm/Date.hpp>
#include <ca-mgm/String.hpp>

#include "Utils.hpp"

using std::endl;

///////////////////////////////////////////////////////////////////
namespace ca_mgm
{ /////////////////////////////////////////////////////////////////

  static std::string adjustLocale();
  static void restoreLocale(const std::string & locale);
  static bool isDST( tm tm );

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : Date::Date
  //	METHOD TYPE : Constructor
  //
  Date::Date( const std::string & seconds_r )
  { str::strtonum( seconds_r, _date ); }

  Date::Date( const std::string & date_str, const std::string & format, bool utc )
    : _date(0)
  {
    struct tm tm = {0,0,0,0,0,0,0,0,0,0,0};
    std::string thisLocale = adjustLocale();

    char * res = ::strptime( date_str.c_str(), format.c_str(), &tm );
    if ( res != NULL )
    {
      if( isDST( tm ) )
      {
        tm.tm_isdst = 1;
      }
      if(utc)
      {
        _date = ::timegm( &tm );
      }
      else
      {
        _date = ::timelocal( &tm );
      }
    }
    restoreLocale(thisLocale);

    if (res == NULL)
      CA_MGM_THROW(ca_mgm::ValueException,
          str::form( __("Invalid date format: '%s'"), date_str.c_str() ).c_str() );
  }

  ///////////////////////////////////////////////////////////////////
  //
  //	METHOD NAME : Date::form
  //	METHOD TYPE : std::string
  //
  std::string Date::form( const std::string & format_r, bool utc ) const
  {
    static char buf[1024];
    std::string thisLocale = adjustLocale();
    if ( utc )
    {
      if ( ! strftime( buf, 1024, format_r.c_str(), gmtime( &_date ) ) )
        *buf = '\0';
    } else {
      if ( ! strftime( buf, 1024, format_r.c_str(), localtime( &_date ) ) )
        *buf = '\0';
    }
    restoreLocale(thisLocale);

    return buf;
  }

  static bool isDST( tm tm )
  {
    time_t t = ::mktime( &tm );
    struct tm *tm2 = ::localtime( &t );
    if( tm2->tm_isdst > 0 )
      return true;
    return false;
  }

  static std::string adjustLocale()
  {
    const char * tmp = ::setlocale( LC_TIME, NULL );
    std::string thisLocale( tmp ? tmp : "" );

    if (    thisLocale.find( "UTF-8" ) == std::string::npos
         && thisLocale.find( "utf-8" ) == std::string::npos
         && thisLocale != "POSIX"
         && thisLocale != "C"
         && thisLocale != "" )
    {
      // language[_territory][.codeset][@modifier]
      // add/exchange codeset with UTF-8
      std::string needLocale = ".UTF-8";
      std::string::size_type loc = thisLocale.find_first_of( ".@" );
      if ( loc != std::string::npos )
      {
        // prepend language[_territory]
        needLocale = thisLocale.substr( 0, loc ) + needLocale;
        loc = thisLocale.find_last_of( "@" );
        if ( loc != std::string::npos )
        {
          // append [@modifier]
          needLocale += thisLocale.substr( loc );
        }
      }
      else
      {
        // append ".UTF-8"
        needLocale = thisLocale + needLocale;
      }
      ::setlocale( LC_TIME, needLocale.c_str() );
    }
    else
    {
      // no need to change the locale
      thisLocale.clear();
    }

    return thisLocale;
  }

  static void restoreLocale(const std::string & locale)
  {
    if ( ! locale.empty() )
      ::setlocale( LC_TIME, locale.c_str() );
  }

  /////////////////////////////////////////////////////////////////
} // namespace zypp
///////////////////////////////////////////////////////////////////
