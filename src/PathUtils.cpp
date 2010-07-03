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

  File:       PathUtils.cpp

  Author:     Michael Calmer
              Michael Andres
  Maintainer: Michael Calmer
/-*/

#include <limal/PathUtils.hpp>
#include <limal/PathInfo.hpp>
#include <limal/Logger.hpp>
#include <limal/String.hpp>
#include "Utils.hpp"

#include <sys/stat.h>
#include <sys/types.h>

namespace LIMAL_NAMESPACE {
namespace path {

using namespace blocxx;

inline static std::string mode2String(mode_t o) {
    std::string s;
    //s.format("%#4o", o);
    s = str::form("0%03o", o);
    return s;
}

inline static std::string errno2String(int e) {
    char buf[blocxx::ExceptionDetail::BUFSZ];
    blocxx::ExceptionDetail::portable_strerror_r(e, buf, sizeof(buf));
    std::string s(buf);
    s += "(" + str::numstring(e) + ")";
    return s;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::createDir
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int createDir( const PathName & path, mode_t mode )
{
    LOGIT_DEBUG("createDir " << path << ' ' << mode2String( mode));
    if(::mkdir( path.toString().c_str(), mode ) == -1 ) {
        LOGIT_ERROR("createDir " << path << ' ' << mode2String( mode) <<
                    " returned " << errno2String(errno));
        return errno;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::createDirRecursive()
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int createDirRecursive( const PathName & path, unsigned mode )
{
    size_t pos, lastpos = 0;
    std::string spath = path.toString()+"/";
    int ret = 0;

    if(path.empty())
        return ENOENT;

    // skip ./
    if(path.relative())
        lastpos=2;
    // skip /
    else
        lastpos=1;

    while((pos = spath.find_first_of('/',lastpos)) != std::string::npos ) {
        std::string dir = spath.substr(0,pos);
        ret = ::mkdir(dir.c_str(), mode);
        if(ret == -1)
            {
                // ignore errors about already existing directorys
                if(errno == EEXIST)
                    ret=0;
                else
                    ret=errno;
            }
        //	DBG << "creating directory " << dir << (ret?" failed":" succeeded") << endl;
        lastpos = pos+1;
    }
    return ret;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::removeDir
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int removeDir( const PathName & path )
{
    LOGIT_DEBUG("removeDir " << path);
    if ( ::rmdir( path.toString().c_str() ) == -1 ) {
        LOGIT_ERROR("removeDir " << path << " returned " << errno2String(errno));
        return errno;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::removeDirRecursive
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int removeDirRecursive( const PathName & path )
{
    LOGIT_DEBUG("removeDirRecursive " << path);
    PathInfo p( path );

    if ( !p.exists() ) {
        return 0;
    }

    if ( !p.isDir() ) {
        return ENOTDIR ;
    }

    std::vector<std::string> cmd;
    cmd.push_back(RM_COMMAND);
    cmd.push_back("-rf");
    cmd.push_back("--preserve-root");
    cmd.push_back("--");
    cmd.push_back(path.toString());

    std::string stdOutput;
    std::string errOutput;
    int    status = -1;
    try {
        status = wrapExecuteProcessAndGatherOutput(
            cmd, stdOutput, errOutput, EnvVars()
        );
    }
    catch(const blocxx::Exception &e) {
        LOGIT_ERROR( "removeDirRecursive exception: " << e);
    }
    if(status != 0) {
        LOGIT_ERROR( "removeDirRecursive status: " << status );
    }
    if(!errOutput.empty()) {
        LOGIT_ERROR( "removeDirRecursive stderr: " << errOutput );
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG( "removeDirRecursive stdout: " << stdOutput );
    }

    return status;
}


///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::copyDir
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int copyDir( const PathName & srcpath, const PathName & destpath )
{
    LOGIT_DEBUG("copyDir " << srcpath << " -> " << destpath );

    PathInfo sp( srcpath );
    if ( !sp.isDir() ) {
        return ENOTDIR;
    }

    PathInfo dp( destpath );
    if ( !dp.isDir() ) {
        return ENOTDIR;
    }

    PathInfo tp( destpath + srcpath.baseName() );
    if ( tp.exists() ) {
        return EEXIST ;
    }

    std::vector<std::string> cmd;
    cmd.push_back(CP_COMMAND);
    cmd.push_back("-a");
    cmd.push_back(srcpath.toString());
    cmd.push_back(destpath.toString());

    std::string stdOutput;
    std::string errOutput;
    int    status = -1;
    try {
        status = wrapExecuteProcessAndGatherOutput(
            cmd, stdOutput, errOutput, EnvVars()
        );
    }
    catch(const blocxx::Exception &e) {
        LOGIT_ERROR( "copyDir exception: " << e);
    }
    if(status != 0) {
        LOGIT_ERROR( "copyDir status: " << status );
    }
    if(!errOutput.empty()) {
        LOGIT_ERROR( "copyDir stderr: " << errOutput );
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG( "copyDir stdout: " << stdOutput );
    }

    return status;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::readDir
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int readDir( std::list<std::string> & retlist,
             const PathName & path, bool dots )
{
    retlist.clear();

    LOGIT_DEBUG("readDir " << path << ' ');

    DIR * dir = ::opendir( path.toString().c_str() );
    if ( ! dir ) {
        LOGIT_ERROR("readDir ::opendir returned " << errno2String(errno));
        return errno;
    }

    struct dirent *entry;
    while ( (entry = ::readdir( dir )) != 0 ) {

        if ( entry->d_name[0] == '.' ) {
            if ( !dots )
                continue;
            if ( entry->d_name[1] == '\0'
                 || (    entry->d_name[1] == '.'
                         && entry->d_name[2] == '\0' ) )
                continue;
        }
        retlist.push_back( entry->d_name );
    }

    ::closedir( dir );

    return 0;
}


///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::removeFile
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int removeFile( const PathName & path )
{
    LOGIT_DEBUG("removeFile " << path);
    if ( ::unlink( path.toString().c_str() ) == -1 ) {
	if(errno == ENOENT)
	{
		// remove a file which does not exist: the result is ok
		// The file does not exist after this call. So return 0.
		return 0;
	}
        LOGIT_ERROR("removeFile "<< path << " returned " << errno2String(errno));
        return errno;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::moveFile
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int moveFile( const PathName & oldpath, const PathName & newpath )
{
    LOGIT_DEBUG("moveFile " << oldpath << " -> " << newpath);
    if ( ::rename( oldpath.toString().c_str(), newpath.toString().c_str() ) == -1 ) {
        LOGIT_ERROR("moveFile " << oldpath << " -> " << newpath << " returned " << errno2String(errno));
        return errno;
    }
    return 0 ;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::copyFile
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int copyFile( const PathName & file, const PathName & dest )
{
    LOGIT_DEBUG("copyFile " << file << " -> " << dest << ' ');

    PathInfo sp( file );
    if ( !sp.isFile() ) {
        LOGIT_ERROR("copyFile " << file << " -> " << dest << ' '
                    <<  "returned: " << errno2String(EINVAL));
        return EINVAL;
    }

    PathInfo dp( dest );
    if ( dp.isDir() ) {
        LOGIT_ERROR("copyFile " << file << " -> " << dest << ' '
                    <<  "returned: " << errno2String(EISDIR));
        return EISDIR;
    }

    std::vector<std::string> cmd;
    cmd.push_back(CP_COMMAND);
    cmd.push_back(file.toString());
    cmd.push_back(dest.toString());

    std::string stdOutput;
    std::string errOutput;
    int    status = -1;
    try {
        status = wrapExecuteProcessAndGatherOutput(
            cmd, stdOutput, errOutput, EnvVars()
        );
    }
    catch(const blocxx::Exception &e) {
        LOGIT_ERROR( "copyFile exception: " << e);
    }
    if(status != 0) {
        LOGIT_ERROR( "copyFile status:" << status );
    }
    if(!errOutput.empty()) {
        LOGIT_ERROR( "copyFile stderr:" << errOutput );
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG( "copyFile stdout:" << stdOutput );
    }

    return status;
}

///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::symLink
//	METHOD TYPE : int
//
//	DESCRIPTION :
//
int symLink( const PathName & oldpath, const PathName & newpath )
{
    LOGIT_DEBUG("symLink " << newpath << " -> " << oldpath);
    if ( ::symlink( oldpath.toString().c_str(), newpath.toString().c_str() ) == -1 ) {
        LOGIT_ERROR("symLink " << newpath << " -> " << oldpath << " returned " << errno2String(errno));
        return errno ;
    }
    return 0;
}


///////////////////////////////////////////////////////////////////
//
//
//	METHOD NAME : PathInfo::changeMode
//	METHOD TYPE : int
//
int changeMode( const PathName & path, mode_t mode )
{
    LOGIT_DEBUG("changeMode " << path << ' ' << mode2String( mode ));
    if ( ::chmod( path.toString().c_str(), mode ) == -1 ) {
        LOGIT_ERROR("changeMode " << path << ' ' << mode2String( mode ) <<
                    " returned " << errno2String(errno));
        return errno;
    }
    return 0;
}

}	// namespace path
}	// namespace LIMAL_NAMESPACE
/* vim: set ts=8 sts=4 sw=4 ai noet: */
