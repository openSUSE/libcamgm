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

  File:       Date.hpp

  Author:     Michael Andres

/-*/
#ifndef CA_MGM_DATE_HPP
#define CA_MGM_DATE_HPP

#include <ctime>
#include <iosfwd>
#include <string>

#include <ca-mgm/Exception.hpp>

///////////////////////////////////////////////////////////////////
namespace ca_mgm
{ /////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////
  //
  //	CLASS NAME : Date
  //
  /** Store and operate on date (time_t).
  */
  class Date
  {
    friend std::ostream & operator<<( std::ostream & str, const Date & obj );

  public:

    typedef time_t ValueType;

    /** Default ctor: 0 */
    Date()
    : _date( 0 )
    {}
    /** Ctor taking time_t value. */
    Date( ValueType date_r )
    : _date( date_r )
    {}
    /** Ctor taking time_t value as string. */
    Date( const std::string & seconds_r );

    /**
     * Ctor from a \a date_str formatted using \a format.
     *
     * \throws DateFormatException in case \a date_str cannot be
     *         parsed according to \a format.
     */
    Date( const std::string & date_str, const std::string & format, bool utc = false);

    /** Return the current time. */
    static Date now()
    { return ::time( 0 ); }

  public:
    /** Conversion to time_t. */
    operator ValueType() const
    { return _date; }

    /** \name Arithmetic operations.
     * \c + \c - \c * \c / are provided via conversion to time_t.
    */
    //@{
    Date & operator+=( const time_t rhs ) { _date += rhs; return *this; }
    Date & operator-=( const time_t rhs ) { _date -= rhs; return *this; }
    Date & operator*=( const time_t rhs ) { _date *= rhs; return *this; }
    Date & operator/=( const time_t rhs ) { _date /= rhs; return *this; }

    Date & operator++(/*prefix*/) { _date += 1; return *this; }
    Date & operator--(/*prefix*/) { _date -= 1; return *this; }

    Date operator++(int/*postfix*/) { return _date++; }
    Date operator--(int/*postfix*/) { return _date--; }
    //@}

  public:
    /** Return string representation according to format.
     * \see 'man strftime' (which is used internaly) for valid
     * conversion specifiers in format.
     *
     * \return An empty string on illegal format.
     **/
    std::string form( const std::string & format_r, bool utc = false ) const;

    /** Default string representation of Date.
     * The preferred date and time representation for the current locale.
     **/
    std::string asString() const
    { return form( "%c" ); }

    /** Convert to string representation of calendar time in
     *  numeric form (like "1029255142").
     **/
    std::string asSeconds() const
    { return form( "%s" ); }

  private:
    /** Calendar time.
     * The number of seconds elapsed since 00:00:00 on January 1, 1970,
     * Coordinated Universal Time (UTC).
     **/
    ValueType _date;
  };
  ///////////////////////////////////////////////////////////////////

  /** \relates Date Stream output */
  inline std::ostream & operator<<( std::ostream & str, const Date & obj )
  { return str << obj.asString(); }

  /////////////////////////////////////////////////////////////////
} // namespace ca_mgm
///////////////////////////////////////////////////////////////////
#endif // CA_MGM_DATE_HPP
