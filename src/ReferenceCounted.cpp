/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file	zypp/base/ReferenceCounted.cc
 *
*/
#include <iostream>

#include <limal/Logger.hpp>
#include <limal/Exception.hpp>
#include <limal/ReferenceCounted.hpp>

///////////////////////////////////////////////////////////////////
namespace ca_mgm
{ /////////////////////////////////////////////////////////////////

    ReferenceCounted::ReferenceCounted()
    : _counter( 0 )
    {
      //DBG << "refcounter set to: " << _counter << std::endl;
    }

    ReferenceCounted::ReferenceCounted( const ReferenceCounted & /*rhs*/ )
    : _counter( 0 )
    {
      //DBG << "CC: refcounter set to: " << _counter << std::endl;
    }

    ReferenceCounted::~ReferenceCounted()
    {
      if ( _counter )
        {
          INF << "~ReferenceCounted: nonzero reference count" << std::endl;
          CA_MGM_THROW(OutOfBoundsException, "~ReferenceCounted: nonzero reference count" );
        }
    }

    void ReferenceCounted::unrefException() const
    {
      INF << "ReferenceCounted::unref: zero reference count" << std::endl;
      CA_MGM_THROW(OutOfBoundsException, "ReferenceCounted::unref: zero reference count" );
    }

    std::ostream & ReferenceCounted::dumpOn( std::ostream & str ) const
    {
      return str << "ReferenceCounted(@" << (const void *)this
                 << "<=" << _counter << ")";
    }

  /////////////////////////////////////////////////////////////////
} // namespace ca_mgm
///////////////////////////////////////////////////////////////////
