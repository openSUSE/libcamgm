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

  File:       PathInfo.hpp

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

   File:       PathInfo.h

   Author:     Michael Andres <ma@suse.de>
   Maintainer: Michael Andres <ma@suse.de>

/-*/
/**
 * @file   PathInfo.hpp
 * @brief  LiMaL path info (stat) utilities.
 */
#ifndef LIMAL_PATH_PATHINFO_HPP
#define LIMAL_PATH_PATHINFO_HPP

#include <limal/ca-mgm/config.h>
#include <limal/PathName.hpp>
#include <blocxx/Map.hpp>

#include <cerrno>
#include <iosfwd>
#include <set>

extern "C"
{
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
}

namespace LIMAL_NAMESPACE {

namespace path {


/**
 * @class PathInfo
 * 
 * @brief Wrapper class for ::stat/::lstat and other file/directory related operations.
 *
 * This wrapper class for ::stat/::lstat can be used like in the following code fragment:
 *
 * @code
 *  PathInfo pi1( "/foo/bar/some_file");            // new object from c-string
 *  PathInfo pi2( PathName( "/foo/bar/some_file");  // new object from PathName object
 *  PathInfo pi3( std::string( "/foo/bar/some_file" ); // new object from std::string

 *  std::cout << "File: \t\t" << pi1 << std::endl;
 *  std::cout << "Type: \t\t" << pi1.fileType() << std::endl; 
 *  std::cout << "UID: \t\t" << pi1.owner() << std::endl;
 *  std::cout << "GID: \t\t" << pi1.group() << std::endl;
 *  std::cout << "#links: \t" << pi1.nlink() << std::endl;
 *
 *  // Note the comment further down on the return value of size()!
 *  std::cout << "size: \t\t" << std::string( pi1.size() ) << std::endl;
 *  std::cout << "blksize: \t" << pi1.blksize() << std::endl;
 *  std::cout << "blocks: \t" << pi1.blocks() << std::endl;
 *  std::cout << "dev: \t\t" << pi1.dev() << std::endl;
 *  std::cout << "ino: \t\t" << pi1.ino() << std::endl;
 *
 *  // Using PathInfo::[a,c,m]time()  
 *  time_t tmpTime = pi1.atime();
 *  struct tm *timeStruct = localtime( &tmpTime );
 *  char *timeFormat = "%d.%m.%Y - %X";
 *  char timeBuf[256];
 *  strftime( timeBuf, sizeof( timeBuf ), timeFormat, timeStruct );
 *  std::cout << "atime: \t\t" << timeBuf << std::endll;
 * @endcode
 *
 */
class PathInfo {

  public:

    enum Mode { E_STAT, E_LSTAT };

    enum FileType {
      NOT_AVAIL  = 0x00, /*!< no type info available */
      NOT_EXIST  = 0x01, /*!< file does not exist */
      T_FILE     = 0x02, /*!< regular file */
      T_DIR      = 0x04, /*!< directory */
      T_CHARDEV  = 0x08, /*!< character device */
      T_BLOCKDEV = 0x10, /*!< block device */
      T_FIFO     = 0x20, /*!< FIFO (named pipe) */
      T_LINK     = 0x40, /*!< symbolic %link */
      T_SOCKET   = 0x80  /*!< socket */
    };

    /**
     * @brief Overloaded << operator. 
     *
     * The << operator is overloaded for FileType objects to produce the following
     * output:
     * @code
     * PathInfo pi("./foo/bar/some_file");
     * std::cout << pi.fileType(); // =="./foo/bar/some_file{<st_mode> <uid>/<gid> [size <size>]"
     * @endcode
     *
     * @param str The std::ostream we want to write to.
     * @param obj The FileType object we want to be written to the ostream.
     *
     * @return A reference to the resulting std::ostream. 
     */
    friend std::ostream & operator<<( std::ostream & str, FileType obj );
    friend std::ostream & operator<<( std::ostream & str, const PathInfo &obj);


    /**
     * @brief Wrapper class for mode_t values as derived from ::stat
     **/
    class StatMode;

    /**
     * @brief Simple cache remembering device/inode to detect hard links.
     *
     */
    class DevInoCache;

  private:

    PathName    m_path;

    struct stat m_statbuf_C;
    Mode        m_mode;
    int         m_error;

  public:


    /**
     * @brief  Constructor to create a PathInfo object from an existing 
     *         PathName object. Initial stat-mode defaults to E_STAT. 
     *
     * @param path      The PathName object used to create the new PathInfo object.
     * @param initial   The stat-mode used when performing stat operations.
     */
    PathInfo( const PathName & path = "", Mode initial = E_STAT );

    /**
     * @brief  Constructor to create a PathInfo object from a std::string.
     *         Initial stat-mode defaults to E_STAT. 
     *
     * @param path      The std::string representing a path which is used 
     *                  to create the new PathInfo object.
     * @param initial   The stat-mode used when performing stat operations.
     */
    PathInfo( const std::string & path, Mode initial = E_STAT );

    /**
     * @brief  Constructor to create a PathInfo object from a c-string.
     *         Initial stat-mode defaults to E_STAT. 
     *
     * @param path      The c-string representing a path which is used to 
     *                  create the new PathInfo object. 
     */
    PathInfo( const char * path, Mode initial = E_STAT );

    /**
     * @brief Destructor. 
     */
    virtual ~PathInfo();
    
    /**
     * @brief  Returns the PathName object this PathInfo object holds.
     * @return The PathName object this PathInfo object holds.
     */ 
    const PathName           path()     const { return m_path; }

    /**
     * @brief  Returns a std::string formed from the PathName object this
     *         this PathInfo object holds.
     * @return A std::string created from the PathName object this PathInfo
     *         object holds.
     */          
    std::string           toString() const { return m_path.toString(); }
    /**
     * @brief  Returns the stat mode which is currently set in this PathInfo 
     *         object.
     * @return The [l]stat mode currently set in this object. Can be either
     *         PathInfo::E_STAT or PathInfo::E_LSTAT.
     */  
    Mode                     mode()     const { return m_mode; }

    /**
     * @brief Returns the internal error code.
     *
     * Returns '-1' if no (l)stat operations has been performed so far.
     * This can be the case if: 
     * - no path has been set so far
     * - path has been changed but no (l)stat operation has been triggered.
     *
     * @return The error code. 
     *
     */
    int                      error()    const { return m_error; }

    /**
     * @brief  Set the path you want to explore to <b>path</b>.
     * @param path   The PathName object you want to investigate.
     */ 
    void                     setPath( const PathName & path );

    /**
     * @brief  Set the [l]stat mode to <b>mode</b>. 
     *
     * When examining a link you get:
     * - information about the link itself, when you are in lstat mode
     * - information about the file the link points to, when you are in stat
     *   mode
     *
     * @param mode   The mode you want to set. Can be PathInfo::E_STAT, or 
     *               PathInfo::E_LSTAT
     * @see Mode
     */
    void                     setMode( Mode mode );


    /**
     * @brief  Performs stat on <b>path</b>.
     *
     * In case stat fails errno is saved and can be acquired with
     * PathInfo::error(). The stat mode remains set to 'E_STAT'.
     *
     * @param  path  The PathName object pointing to the path you want to 
     *               investigate.
     *
     * @return True on success, false if stat fails. 
     *
     */
    bool                     stat   ( const PathName & path );

     /**
     * @brief  Performs lstat on path. 
     *
     * In case lstat fails errno is saved and can be acquired with
     * PathInfo::error(). The stat mode remains set to 'E_LSTAT'.
     *
     * @param  path  A PathName object pointing to the path you want to 
     *               investigate.
     *
     * @return True on success, false if lstat fails. 
     *
     */
    bool                     lstat  ( const PathName & path );


    /**
     * @brief  Sets the PathInfo object to <b>path</b> and performs (l)stat on
     *         on it. 
     *   
     * Which function is called depends on the current stat mode (default: E_STAT). 
     * On error errno is saved and can be acquired via PathInfo::error().
     *
     *
     * @param  path  A PathName object point to the path you want to 
     *               investigate.
     *
     * @return True on success, false if (l)stat fails.
     *
     */
    bool                     operator()( const PathName & path );


    /**
     * @brief  Performs a stat operation on the path currently held by this PathInfo
     *         object. 
     *
     * On error errno is saved an can be acquired via PathInfo::error(). 
     * The stat mode remains set to 'E_STAT'
     *
     * @return True on success, false if stat fails.
     *
     */
    bool                     stat();
    
     /**
     * @brief  Performs a lstat operation on the path currently held by this PathInfo
     *         object.
     *
     * On error errno is saved an can be acquired via PathInfo::error(). 
     * The stat mode remains set to 'E_LSTAT'
     *
     * @return True on success, false if lstat fails.
     *
     */
    bool                     lstat();

    /**
     * @brief Performs (l)stat on current path. 
     *
     * Depending on the current stat mode this operator performs either stat, 
     * or lstat. On error errno is saved and can be acquired via PathInfo::error().
     *
     * @return True on success, false of (l)stat fails.
     *
     */
    bool                     operator()();



    /**
     * @brief True if the path that this PathInfo object points to exists. 
     *
     *
     * @return True if path exists.
     *
     */
    bool                     exists() const { return !m_error; }

    /**
     * @name File type functions.
     */
    // @{ 
    /**
     * @brief Returns the file type.
     *
     * @return The file type. 
     * @see FileType
     */ 
    FileType                 fileType() const;


    /**
     * @brief Check if the PathInfo object points to a regular file. 
     */
    bool                     isFile()  const;
    
    /**
     * @brief Check if the PathInfo object points to a directory. 
     */
    bool                     isDir ()  const;
    
    /**
     * @brief Check if the PathInfo object points to a symbolic %link. 
     */
    bool                     isLink()  const;
    
    /**
     * @brief Check if the PathInfo object points to a character device. 
     */
    bool                     isChr()   const;
    
    /**
     * @brief Check if the PathInfo object points to a block device. 
     */
    bool                     isBlk()   const;
    
    /**
     * @brief Check if the PathInfo object points to a FIFO (named pipe). 
     */
    bool                     isFifo()  const;
    
    /**
     * @brief Check if the PathInfo object points to a socket. 
     */
    bool                     isSock()  const;

    // @}

    /**
     * @brief  Returns the number of hard links to the file the PathName object
     *         points to. 
     *
     * @return Number of hard links to the file.
     */
    nlink_t                  nlink()  const;

    /**
     * @brief Get the user ID of the file owner. 
     *
     *
     * @return Uid of file owner.
     *
     */
    uid_t                    owner()   const;

    /**
     * @brief Get the group ID of the file owner. 
     *
     *
     * @return Gid of file owner. 
     *
     */
    gid_t                    group()   const;

    /**
     * @name Permissions
     *
     * The following functions can be used to check for file permissions.
     * Their functionality closely resembles the POSIX flags 
     * mentioned in 'man [l]stat'. 
     */
    // @{
    /** @brief Check if owner has read permission. */
    bool                     isRUsr()  const;
    /** @brief Check if owner has write permission. */
    bool                     isWUsr()  const;
    /** @brief Check if owner has execute permission. */
    bool                     isXUsr()  const;
 
    /** @see isRUsr() */
    bool                     isR()     const;
    /** @see isWUsr() */
    bool                     isW()     const;
    /** @see isXUsr() */
    bool                     isX()     const;

    /** @brief Check if group has read permission. */
    bool                     isRGrp()  const;
    /** @brief Check if group has write permission. */
    bool                     isWGrp()  const;
    /** @brief Check if group has execute permission. */
    bool                     isXGrp()  const;

    /** @brief Check if others have read permission. */
    bool                     isROth()  const;
    /** @brief Check if others have write permission. */
    bool                     isWOth()  const;
    /** @brief Check if others have execute permission. */
    bool                     isXOth()  const;

    /** @brief Check if 'set UID bit" is set. */
    bool                     isUid()   const;
    /** @brief Check if 'set GID bit" is set. */
    bool                     isGid()   const;
    /** @brief Check if 'sticky bit" is set. */
    bool                     isVtx()   const;

    /** @brief Get the file owner permissions.
     * 
     * All other flags are masked out (masked to 0).
     *
     * @return The masked mode_t.
     */
    mode_t                   uperm()   const;
    
    /** @brief Get the file group permissions.
     * 
     * All other flags are masked out (masked to 0).
     *
     * @return The masked mode_t.
     */
    mode_t                   gperm()   const;
    
    /** @brief Get the file permissions for others.
     * 
     * All other flags are masked out (masked to 0).
     *
     * @return The masked mode_t.
     */
    mode_t                   operm()   const;

    /** @brief Get the complete file permissions.
     *
     * @return The ( mode_t & S_IRWXU|S_IRWXG|S_IRWXO|S_ISUID|S_ISGID|S_ISVTX ).
     */
    mode_t                   perm()    const;


    /**
     * @brief Check if file has given permissions.
     *
     *
     * @param  m The mode_t you want the file to be checked for.
     *
     * @return True if given mode_t matches the files' mode_t.
     *
     */
    bool                     isPerm ( mode_t m ) const;
    
     /**
     * @brief Check if file has given permission flags set.
     *
     *
     * @param  m The mode_t flags you want the file to be checked for.
     *
     * @return True if given mode_t flags matches the files' flags.
     *
     */
    bool                     hasPerm( mode_t m ) const;

    /**
     * @brief  Returns the mode (i.e. file access permissions) of the file.
     *
     * From the lstat man page: 
     * The following POSIX macros are defined to check the file type:
     * - S_ISREG(mode_t)  is it a regular file?
     * - S_ISDIR(mode_t)  directory?
     * - S_ISCHR(mode_t)  character device?
     * - S_ISBLK(mode_t)  block device?
     * - S_ISFIFO(mode_t) FIFO (named pipe)?
     * - S_ISLNK(mode_t)  symbolic link? (Not in POSIX.1-1996.)
     * - S_ISSOCK(mode_t) socket? (Not in POSIX.1-1996.)
     *
     * @return The access permissions of the file. 
     */
    mode_t                   st_mode() const;

    /**
     * @brief Get permission according to current uid/gid 
     *
     * @return The current users' permissions on the file [0-7].
     */
    mode_t                   userMay() const;


    /**
     * @brief Check if the current User (as returned by getuid()) may read the file. 
     *
     * @return True if current user has read permissions. 
     *
     */
    bool                     userMayR() const;
    
    /**
     * @brief Check if the current User (as returned by getuid()) may write to the file. 
     *
     * @return True if current user has write permissions. 
     *
     */
    bool                     userMayW() const;
    
    /**
     * @brief Check if the current User (as returned by getuid()) may execute the file. 
     *
     * @return True if current user has execute permissions. 
     *
     */
    bool                     userMayX() const;

     /**
     * @brief Check if the current User (as returned by getuid()) may read and write
     * the file. 
     *
     * @return True if current user has read and write permissions. 
     *
     */
    bool                     userMayRW()  const;
    
    /**
     * @brief Check if the current User (as returned by getuid()) may read and execute
     *  the file. 
     *
     * @return True if current user has read and execute permissions. 
     *
     */
    bool                     userMayRX()  const;
   
    /**
     * @brief Check if the current User (as returned by getuid()) may write and execute 
     * the file. 
     *
     * @return True if current user has write and execute permissions. 
     *
     */
    bool                     userMayWX()  const;

    /**
     * @brief Check if the current User (as returned by getuid()) may read, write and 
     * execute the file. 
     *
     * @return True if current user has read, write and execute permissions. 
     *
     */
    bool                     userMayRWX() const;
 
    // @}

    // device

    /**
     * @brief  Returns the ID of the device that contains the file.
     *
     * @return The device id that contains the file. 
     */
    dev_t                    dev()     const;

    /**
     * @brief Returns the device ID of a special file.
     *
     * @return The device ID of the file (in case of a special file). 
     */
    dev_t                    rdev()    const;

    /**
     * @brief Returns the inode number of the file or directory this PathInfo
     *        object holds. 
     *
     * @return The inode number.
     */
    ino_t                    ino()     const;

    /**
     * @brief Returns the size of the file.
     *
     * @return The size of the file.
     *
     * @note The off_t type may be of type "long long" (64bit) and
     * the stream operator "<<" may convert off_t to int, causing
     * unexpected wrong outputs.
     * You can workaround it using std::string(p.size()), that
     * provides proper conversion constructors for 64bit integers.
     */
    ::off_t                  size()    const;

    /**
     * @brief  Returns the block size of the file.
     *
     * @return The block size of the file.
     *
     */
    blksize_t                blksize() const;

    /**
     * @brief  Returns the number of blocks used by the file.
     *
     * @return The number of blocks used by the file. 
     *
     */
    blkcnt_t                 blocks()  const;

    /** @name time functions */
    // @{
    /**
     * @brief Get the access time of the file.
     *
     * @return The access time as a UNIX time stamp.
     */ 
    time_t                   atime()   const; /* time of last access */
    
    /**
     * @brief  Get the time of the last modification of the file. 
     *
     * @return The modification time as a UNIX time stamp.
     */ 
    time_t                   mtime()   const; /* time of last modification */
    
    /**
     * @brief Get the last-change time of inode status of the file. 
     *
     * @return The last-change time as a UNIX time stamp.
     */ 
    time_t                   ctime()   const;

    // @}
};

///////////////////////////////////////////////////////////////////

/**
 * @class PathInfo::StatMode
 * 
 * @brief Wrapper class for mode_t values as derived from ::stat
 */
class PathInfo::StatMode {

  friend std::ostream & operator<<( std::ostream & str, const PathInfo::StatMode & obj );

  private:
    mode_t _mode;
  public:
    StatMode( const mode_t & mode_r = 0 ) : _mode( mode_r ) {}

    /** 
     * @name file type wrapper functions 
     *
     * For a more detailed description of these functions see the corresponding 
     * PathInfo (don't know why doxy-gen doesn't create a %link to the PathInfo doc here)
     * functions.
     */
    // @{
    FileType fileType() const;

    bool     isFile()  const;
    bool     isDir ()  const;
    bool     isLink()  const;
    bool     isChr()   const;
    bool     isBlk()   const;
    bool     isFifo()  const;
    bool     isSock()  const;
    // @}
    
    /** @name file permission wrapper functions */
    // @{
    bool     isRUsr()  const;
    bool     isWUsr()  const;
    bool     isXUsr()  const;

    bool     isR()     const;
    bool     isW()     const;
    bool     isX()     const;

    bool     isRGrp()  const;
    bool     isWGrp()  const;
    bool     isXGrp()  const;

    bool     isROth()  const;
    bool     isWOth()  const;
    bool     isXOth()  const;

    bool     isUid()   const;
    bool     isGid()   const;
    bool     isVtx()   const;

    mode_t   uperm()   const;
    mode_t   gperm()   const;
    mode_t   operm()   const;
    mode_t   perm()    const;

    bool     isPerm( mode_t m ) const;
    bool     hasPerm( mode_t m ) const;

    mode_t   st_mode() const;

    // @}
};

///////////////////////////////////////////////////////////////////

/**
 * @brief Simple cache remembering device/inode to detect hard links.
 * @code
 *     PathInfo::DevInoCache trace;
 *     for ( all files ) {
 *       if ( trace.insert( file.device, file.inode ) ) {
 *         // 1st occurrence of file
 *       }
 *       else{
 *         // else: hard link; already counted this device/inode
 *       }
 *     }
 * @endcode
 **/
class PathInfo::DevInoCache {

  private:

    std::map<dev_t,std::set<ino_t> > _devino;

  public:
    /**
     * @brief Constructor
     **/
    DevInoCache() {}

    /**
     * @brief Clear cache.
     **/
    void clear() { _devino.clear(); }

    /**
     * @brief Remember dev/ino. 
     *
     * @return 
     *         - <code>true</code> if it's inserted the first time 
     *         - <code>false</code> if already present in cache (a hard link to a
     * previously remembered file.
     **/
    bool insert( const dev_t & dev_r, const ino_t & ino_r ) {
      return _devino[dev_r].insert( ino_r ).second;
    }
};

///////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////

}
}

#endif // LIMAL_PATH_PATHINFO_HPP
