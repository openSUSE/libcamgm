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

  File:       PathUtils.hpp

  Author:     Michael Calmer
              Michael Andres
  Maintainer: Michael Calmer

  Purpose:

/-*/
/**
 * @file   PathUtils.hpp
 * @brief  LiMaL path related utilities.
 * @todo Review this file/classes.
 * @todo Reimplement functions in PathUtils to not to execute commands!
 */
#ifndef LIMAL_PATH_UTILS_HPP
#define LIMAL_PATH_UTILS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/PathName.hpp>
#include  <blocxx/List.hpp>


namespace LIMAL_NAMESPACE
{

/**
 * @brief  The LiMaL path utility namespace.
 */ 
namespace path
{

    /**
     * @brief Create a directory.
     * 
     * Like '::mkdir'. Attempt to create a new directory with name 'path'.
     * The parameter 'mode' specifies the permissions bits to use. It is
     * modified by the process's umask in the usual way.
     *
     * The directory's user ID is set to the process' effective user ID, the
     * group ID to the effective group ID of the process or inherited from
     * the parent directory if the set group ID bit is set or if specified
     * by mount options.
     *
     * @param path The path name of the new directory.
     * @param mode The permissions bits of the new directory.
     *
     * @return 0 on success, errno value on failure
     */
    int createDir(const PathName &path, mode_t mode = 0755);


    /**
     * @bried Create a directory with parent directories as needed.
     *
     * Like 'mkdir -p'. Attempt to create a new directory with name 'path'
     * and all parent directories as needed. The parameter 'mode' specifies
     * the permissions bits to use. It is modified by the process's umask
     * in the usual way.
     * No error is reported if the directory already exists.
     *
     * @param path The path name of the new directory.
     * @param mode The permissions bits of the new directory.
     *
     * @return 0 on success, errno value on failure
     **/
    int createDirRecursive(const PathName &path, mode_t mode = 0755);


   /**
     * @brief Remove a directory.
     *
     * Like '::rmdir'. Delete a directory, which must be empty.
     * 
     * @param path The path to the directory.
     *
     * @return 0 on success, errno value on failure
     */
    int removeDir(const PathName& path);


    /**
     * @brief Remove a directory recursively.
     *
     * Like 'rm -r path'. Delete a directory, recursively removing its
     * contents.
     * 
     * @param path The path to the directory.
     *
     * @return 0 on success, ENOTDIR if the specified path is not a directory,
     * otherwise the commands return value.
     *
     * @todo Rewrite not to execute shell command 'rm -rf --preserve-root -- <path>'.
     */
    int removeDirRecursive(const PathName& path );


    /**
     * Like 'cp -a srcPath destPath'. Copy directory tree. srcpath/destpath must be
     * directories. 'basename srcpath' must not exist in destpath.
     *
     * @return 0 on success, ENOTDIR if srcpath/destpath is not a directory, EEXIST if
     * 'basename srcpath' exists in destpath, otherwise the commands return value.
     *
     * @todo Rewrite not to execute shell command 'cp -a <srcPath> <destPath>'
     **/
    int copyDir(const PathName& srcPath, const PathName& destPath);

    /**
     * Return content of directory via retlist. If dots is false
     * entries starting with '.' are not reported. "." and ".."
     * are never reported.
     *
     * @return 0 on success, errno on failure.
     **/
    int readDir(std::list<blocxx::String> & retlist,
                const PathName& path, bool dots);

    /**
     * Like '::unlink'. Delete a file (symbolic link, socket, fifo or device).
     *
     * @return 0 on success, errno on failure
     **/
    int removeFile(const PathName& path);

    /**
     * Like '::rename'. Renames a file, moving it between directories if required.
     *
     * @return 0 on success, errno on failure
     **/
    int moveFile(const PathName& oldPath, const PathName& newPath);

    /**
     * Like 'cp file dest'. Copy file to destination file.
     *
     * @return 0 on success, EINVAL if file is not a file, EISDIR if
     * destiantion is a directory, otherwise the commands return value.
     **/
    int copyFile(const PathName& file, const PathName& dest);

    /**
     * Like '::symlink'. Creates a symbolic link named newpath which contains
     * the string oldpath. If newpath exists it will not be overwritten.
     *
     * @return 0 on success, errno on failure.
     **/
    int symLink(const PathName& oldPath, const PathName& newPath);

    /**
     * Like '::chmod'. The mode of the file given by path is changed.
     *
     * @return 0 on success, errno on failure
     **/
    int changeMode(const PathName& path, mode_t mode);

    /**
     * ??? Or String ???
     */
    // int changeOwner(const PathName& path, const String& uid, const String& gid);

}
}

#endif /* LIMAL_PATH_UTILS_HPP */
