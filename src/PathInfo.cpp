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

  File:       PathInfo.cpp

  Maintainer: Michael Calmer

/----------------------------------------------------------------------\
|                                                                      |
|                      __   __    ____ _____ ____                      |
|                      \ \ / /_ _/ ___|_   _|___ \                     |
|                       \ V / _` \___ \ | |   __) |                    |
|                        | | (_| |___) || |  / __/                     |
|                        |_|\__,_|____/ |_| |_____|                    |
|                                                                      |
|                               core system                            |
|                                                        (C) SuSE GmbH |
\----------------------------------------------------------------------/

   File:       PathInfo.cc

   Author:     Michael Andres <ma@suse.de>
   Maintainer: Michael Andres <ma@suse.de>

/-*/

#include <limal/PathInfo.hpp>

#include <iostream>
#include <fstream>
#include <iomanip>

namespace LIMAL_NAMESPACE {
namespace path {

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::PathInfo
//	METHOD TYPE : Constructor
//
//	DESCRIPTION :
//
PathInfo::PathInfo( const PathName & path, Mode initial )
    : m_path( path )
    , m_mode( initial )
    , m_error( -1 )
{
  operator()();
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::PathInfo
//	METHOD TYPE : Constructor
//
//	DESCRIPTION :
//
PathInfo::PathInfo( const std::string & path, Mode initial )
    : m_path( path )
    , m_mode( initial )
    , m_error( -1 )
{
  operator()();
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::PathInfo
//	METHOD TYPE : Constructor
//
//	DESCRIPTION :
//
PathInfo::PathInfo( const char * path, Mode initial )
    : m_path( path )
    , m_mode( initial )
    , m_error( -1 )
{
  operator()();
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::~PathInfo
//	METHOD TYPE : Destructor
//
//	DESCRIPTION :
//
PathInfo::~PathInfo()
{
}

void
PathInfo::setPath(const PathName& path)
{
    if ( path != m_path )
        m_error = -1;
    m_path = path;
}

void
PathInfo::setMode(Mode mode)
{
    if(mode != m_mode)
        m_error = -1;
    m_mode = mode;
}

bool
PathInfo::stat(const PathName& path )
{
    setPath( path );
    setMode( E_STAT );
    return operator()();
}

bool
PathInfo::lstat(const PathName& path)
{
    setPath( path );
    setMode( E_LSTAT );
    return operator()();
}

bool
PathInfo::operator()(const PathName& path)
{
    setPath( path );
    return operator()();
}

bool
PathInfo::stat()
{
    setMode( E_STAT );
    return operator()();
}

bool
PathInfo::lstat()
{
    setMode( E_LSTAT );
    return operator()();
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::operator()
//	METHOD TYPE : bool
//
//	DESCRIPTION :
//
bool PathInfo::operator()()
{
  if ( m_path.empty() ) {
    m_error = -1;
  } else {
    switch ( m_mode ) {
    case E_STAT:
      m_error = ::stat( m_path.toString().c_str(), &m_statbuf_C );
      break;
    case E_LSTAT:
      m_error = ::lstat( m_path.toString().c_str(), &m_statbuf_C );
      break;
    }
    if ( m_error == -1 )
      m_error = errno;
  }
  return !m_error;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::fileType
//	METHOD TYPE : PathInfo::FileType
//
PathInfo::FileType PathInfo::fileType() const
{
  if ( exists() )
    return StatMode( st_mode() ).fileType();
  return NOT_EXIST;
}

bool
PathInfo::isFile() const
{
    return exists() && S_ISREG( m_statbuf_C.st_mode );
}

bool
PathInfo::isDir() const
{
    return exists() && S_ISDIR( m_statbuf_C.st_mode );
}

bool
PathInfo::isLink() const
{
    return exists() && S_ISLNK( m_statbuf_C.st_mode );
}

bool
PathInfo::isChr() const
{
    return exists() && S_ISCHR( m_statbuf_C.st_mode );
}

bool
PathInfo::isBlk() const
{
    return exists() && S_ISBLK( m_statbuf_C.st_mode );
}

bool
PathInfo::isFifo() const
{
    return exists() && S_ISFIFO( m_statbuf_C.st_mode );
}

bool
PathInfo::isSock() const
{
    return exists() && S_ISSOCK( m_statbuf_C.st_mode );
}

nlink_t
PathInfo::nlink() const
{
    return exists() ? m_statbuf_C.st_nlink : 0;
}

// owner
uid_t
PathInfo::owner() const
{
    return exists() ? m_statbuf_C.st_uid : 0;
}

gid_t
PathInfo::group() const
{
    return exists() ? m_statbuf_C.st_gid : 0;
}

// permission
bool
PathInfo::isRUsr() const
{
    return exists() && (m_statbuf_C.st_mode & S_IRUSR);
}

bool
PathInfo::isWUsr() const
{
    return exists() && (m_statbuf_C.st_mode & S_IWUSR);
}

bool
PathInfo::isXUsr() const
{
    return exists() && (m_statbuf_C.st_mode & S_IXUSR);
}

bool
PathInfo::isR() const
{
    return isRUsr();
}

bool
PathInfo::isW() const
{
    return isWUsr();
}

bool
PathInfo::isX() const
{
    return isXUsr();
}

bool
PathInfo::isRGrp() const
{
    return exists() && (m_statbuf_C.st_mode & S_IRGRP);
}

bool
PathInfo::isWGrp() const
{
    return exists() && (m_statbuf_C.st_mode & S_IWGRP);
}

bool
PathInfo::isXGrp() const
{
    return exists() && (m_statbuf_C.st_mode & S_IXGRP);
}

bool
PathInfo::isROth() const
{
    return exists() && (m_statbuf_C.st_mode & S_IROTH);
}

bool
PathInfo::isWOth() const
{
    return exists() && (m_statbuf_C.st_mode & S_IWOTH);
}

bool
PathInfo::isXOth() const
{
    return exists() && (m_statbuf_C.st_mode & S_IXOTH);
}

bool
PathInfo::isUid() const
{
    return exists() && (m_statbuf_C.st_mode & S_ISUID);
}

bool
PathInfo::isGid() const
{
    return exists() && (m_statbuf_C.st_mode & S_ISGID);
}

bool
PathInfo::isVtx() const
{
    return exists() && (m_statbuf_C.st_mode & S_ISVTX);
}

mode_t
PathInfo::uperm() const
{
    return exists() ? (m_statbuf_C.st_mode & S_IRWXU) : 0;
}

mode_t
PathInfo::gperm() const
{
    return exists() ? (m_statbuf_C.st_mode & S_IRWXG) : 0;
}

mode_t
PathInfo::operm() const
{
    return exists() ? (m_statbuf_C.st_mode & S_IRWXO) : 0;
}

mode_t
PathInfo::perm()  const
{
    return exists() ? (m_statbuf_C.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO|S_ISUID|S_ISGID|S_ISVTX)) : 0;
}

bool
PathInfo::isPerm( mode_t m ) const
{
    return (m == perm());
}

bool
PathInfo::hasPerm( mode_t m ) const
{
    return (m == (m & perm()));
}

mode_t
PathInfo::st_mode() const
{
    return exists() ? m_statbuf_C.st_mode : 0;
}


///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::userMay
//	METHOD TYPE : mode_t
//
//	DESCRIPTION :
//
mode_t PathInfo::userMay() const
{
    if ( !exists() )
        return 0;
    if ( owner() == getuid() ) {
        return( uperm()/0100 );
    } else if ( group() == getgid() ) {
        return( gperm()/010 );
    }
    return operm();
}

bool
PathInfo::userMayR() const
{
    return( userMay() & 04 );
}

bool
PathInfo::userMayW() const
{
    return( userMay() & 02 );
}

bool
PathInfo::userMayX() const
{
    return( userMay() & 01 );
}

bool
PathInfo::userMayRW() const
{
    return( (userMay() & 06) == 06 );
}

bool
PathInfo::userMayRX() const
{
    return( (userMay() & 05) == 05 );
}

bool
PathInfo::userMayWX() const
{
    return( (userMay() & 03) == 03 );
}

bool
PathInfo::userMayRWX() const
{
    return( userMay() == 07 );
}

// device
dev_t
PathInfo::dev() const
{
    return exists() ? m_statbuf_C.st_dev  : 0;
}

dev_t
PathInfo::rdev() const
{
    return exists() ? m_statbuf_C.st_rdev : 0;
}

ino_t
PathInfo::ino() const
{
    return exists() ? m_statbuf_C.st_ino  : 0;
}

::off_t
PathInfo::size() const
{
    return exists() ? m_statbuf_C.st_size : 0;
}

blksize_t
PathInfo::blksize() const
{
    return exists() ? m_statbuf_C.st_blksize : 0;
}

blkcnt_t
PathInfo::blocks() const
{
    return exists() ? m_statbuf_C.st_blocks  : 0;
}

// time
time_t
PathInfo::atime() const
{
    /* time of last access */
    return exists() ? m_statbuf_C.st_atime : 0;
}

time_t
PathInfo::mtime() const
{
    /* time of last modification */
    return exists() ? m_statbuf_C.st_mtime : 0;
}

time_t
PathInfo::ctime() const
{
    return exists() ? m_statbuf_C.st_ctime : 0;
}

/******************************************************************
**
**
**	FUNCTION NAME : operator<<
**	FUNCTION TYPE : ostream &
**
**	DESCRIPTION :
*/
std::ostream & operator<<( std::ostream & str, const PathInfo & obj )
{
    std::ios::fmtflags state_ii = str.flags();

    str << obj.toString() << "{";
    if ( !obj.exists() ) {
        str << "does not exist}";
    } else {
        str << PathInfo::StatMode( obj.st_mode() ) << " " << std::dec
            << obj.owner() << "/" << obj.group();

        if ( obj.isFile() )
            str << " size " << obj.size();

        str << "}";
    }
    str.flags( state_ii );
    return str;
}

/******************************************************************
**
**
**	FUNCTION NAME : operator<<
**	FUNCTION TYPE : std::ostream &
**
**	DESCRIPTION :
*/
std::ostream & operator<<( std::ostream & str, PathInfo::FileType obj )
{
  switch ( obj ) {
#define EMUMOUT(T) case PathInfo::T: return str << #T; break
    EMUMOUT( NOT_AVAIL );
    EMUMOUT( NOT_EXIST );
    EMUMOUT( T_FILE );
    EMUMOUT( T_DIR );
    EMUMOUT( T_CHARDEV );
    EMUMOUT( T_BLOCKDEV );
    EMUMOUT( T_FIFO );
    EMUMOUT( T_LINK );
    EMUMOUT( T_SOCKET );
#undef EMUMOUT
  }
  return str;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::StatMode::fileType
//	METHOD TYPE : PathInfo::FileType
//
PathInfo::FileType PathInfo::StatMode::fileType() const
{
  if ( isFile() )
    return T_FILE;
  if ( isDir() )
    return T_DIR;
  if ( isLink() )
    return T_LINK;
  if ( isChr() )
    return T_CHARDEV;
  if ( isBlk() )
    return T_BLOCKDEV;
  if ( isFifo() )
    return T_FIFO;
  if ( isSock() )
    return T_SOCKET ;

  return NOT_AVAIL;
}

bool
PathInfo::StatMode::isFile() const
{
    return S_ISREG( _mode );
}

bool
PathInfo::StatMode::isDir () const
{
    return S_ISDIR( _mode );
}

bool
PathInfo::StatMode::isLink() const
{
    return S_ISLNK( _mode );
}

bool
PathInfo::StatMode::isChr() const
{
    return S_ISCHR( _mode );
}

bool
PathInfo::StatMode::isBlk() const
{
    return S_ISBLK( _mode );
}

bool
PathInfo::StatMode::isFifo() const
{
    return S_ISFIFO( _mode );
}

bool
PathInfo::StatMode::isSock() const
{
    return S_ISSOCK( _mode );
}

// permission
bool
PathInfo::StatMode::isRUsr() const
{
    return (_mode & S_IRUSR);
}

bool
PathInfo::StatMode::isWUsr() const
{
    return (_mode & S_IWUSR);
}

bool
PathInfo::StatMode::isXUsr() const
{
    return (_mode & S_IXUSR);
}

bool
PathInfo::StatMode::isR() const
{
    return isRUsr();
}

bool
PathInfo::StatMode::isW() const
{
    return isWUsr();
}

bool
PathInfo::StatMode::isX() const
{
    return isXUsr();
}

bool
PathInfo::StatMode::isRGrp() const
{
    return (_mode & S_IRGRP);
}

bool
PathInfo::StatMode::isWGrp() const
{
    return (_mode & S_IWGRP);
}

bool
PathInfo::StatMode::isXGrp() const
{
    return (_mode & S_IXGRP);
}

bool
PathInfo::StatMode::isROth() const
{
    return (_mode & S_IROTH);
}

bool
PathInfo::StatMode::isWOth() const
{
    return (_mode & S_IWOTH);
}

bool
PathInfo::StatMode::isXOth() const
{
    return (_mode & S_IXOTH);
}

bool
PathInfo::StatMode::isUid() const
{
    return (_mode & S_ISUID);
}

bool
PathInfo::StatMode::isGid() const
{
    return (_mode & S_ISGID);
}

bool
PathInfo::StatMode::isVtx() const
{
    return (_mode & S_ISVTX);
}

mode_t
PathInfo::StatMode::uperm() const
{
    return (_mode & S_IRWXU);
}

mode_t
PathInfo::StatMode::gperm() const
{
    return (_mode & S_IRWXG);
}

mode_t
PathInfo::StatMode::operm() const
{
    return (_mode & S_IRWXO);
}

mode_t
PathInfo::StatMode::perm() const
{
    return (_mode & (S_IRWXU|S_IRWXG|S_IRWXO|S_ISUID|S_ISGID|S_ISVTX));
}

bool
PathInfo::StatMode::isPerm( mode_t m ) const
{
    return (m == perm());
}

bool
PathInfo::StatMode::hasPerm( mode_t m ) const
{
    return (m == (m & perm()));
}

mode_t
PathInfo::StatMode::st_mode() const
{
    return _mode;
}


/******************************************************************
**
**
**	FUNCTION NAME : operator<<
**	FUNCTION TYPE : std::ostream &
**
**	DESCRIPTION :
*/
std::ostream & operator<<( std::ostream & str, const PathInfo::StatMode & obj )
{
  char t = '?';
  if ( obj.isFile() )
    t = '-';
  else if ( obj.isDir() )
    t = 'd';
  else if ( obj.isLink() )
    t = 'l';
  else if ( obj.isChr() )
    t = 'c';
  else if ( obj.isBlk() )
    t = 'b';
  else if ( obj.isFifo() )
    t = 'p';
  else if ( obj.isSock() )
    t = 's';

  str << t << " " << std::setfill( '0' ) << std::setw( 4 ) << std::oct << obj.perm() << std::dec;
  return str;
}

}	// namespace path
}	// namespace LIMAL_NAMESPACE
