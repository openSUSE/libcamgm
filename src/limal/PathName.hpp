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

  File:       PathName.hpp

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

   File:       Pathname.h

   Author:     Michael Andres <ma@suse.de>
   Maintainer: Michael Andres <ma@suse.de>

/-*/
/**
 * @file   PathName.hpp
 * @brief  LiMaL path name manipulation utilities.
 */
#ifndef LIMAL_PATH_PATHNAME_HPP
#define LIMAL_PATH_PATHNAME_HPP

#include <limal/ca-mgm/config.h>
#include <limal/String.hpp>
#include <list>
#include <iosfwd>


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace path
{

// -------------------------------------------------------------------
/**
 * @brief PathName manipulation class.
 *
 * This class is intended for internal usage inside of LiMaL
 * pluglibs and should never appear in the pluglib interface.
 *
 */
class PathName
{
public:
    typedef std::list<std::string> List;

    /**
    * @brief Create an empty PathName object.
    *
    */
    PathName();

    /**
    * @brief Create a Copy of a PathName object.
    * @param path The PathName object to be copied.
    */
    PathName(const PathName       &path);

    /**
    * @brief Create a new PathName object from a PathName::List.
    * @param list The PathName::List from which the new PathName
    * object shall be created. The first element of this List has
    * to be a prefix, or if there is no prefix an empty string.
    * @throws ca_mgm::ValueException
    */
    PathName(const PathName::List &list);

    /**
    * @brief Create a new PathName object from a std::string.
    * @param name The string from which the new PathName object
    * shall be created.
    * @throws ca_mgm::ValueException
    */
    PathName(const std::string &name);
    /**
    * @brief Create a new PathName object from a c string.
    * @param name The character pointer to the c string from which
    * the new PathName object shall be created.
    * @throws ca_mgm::ValueException
    */
    PathName(const char           *name);

    /**
    * Destructor
    */
    virtual ~PathName();

   /**
    * @brief Assigns <b>path</b> to	this PathName object and returns a
    * reference to it.
    *
    * @param path The PathName object to assign.
    * @return A reference to this PathName object.
    */
    PathName & operator= (const PathName &path);

    /**
    * @brief Appends <b>path</b> to this PathName object and
    * a reference to it.
    *
    * @param path The PathName object that is to be appended.
    *
    * @return A reference to this PathName object.
    */
    PathName & operator+=(const PathName &path);

    /**
    * @brief Returns the complete path this PathName object holds.
    *
    * @return The complete path this PathName object holds.
    */
    std::string          toString() const;

    /**
    * @brief Returns the path this PathName object holds, as
    * a PathName::List. The first element of that list is
    * either the prefix, or, if there is no drive prefix it's an
    * empty string.
    *
    * @return The complete path this PathName object holds, as
    * a PathName::List.
    *
    * @throws ca_mgm::ValueException
    */
    PathName::List          toList()   const;

    /**
    * @brief Returns the path prefix if existent, otherwise ""
    *
    * Returns the path prefix (i.e. drive letter), if the path this
    * PathName object holds contains one (like in 'c:/foo/bar'),
    * otherwise the empty string will be returned.
    *
    * @return prefix/drive letter or the empty string
    */
    std::string          prefix()   const;

    /**
    * @brief Returns true if this PathName object holds an empty path.
    *
    * @return True if this PathName object holds an empty path.
    */
    bool                    empty()    const;

    /**
    * @brief Returns true if this PathName object holds an absolute Path.
    *
    * @return True if this PathName object holds an absolute path
    * (like '/foo/bar').
    */
    bool                    absolute() const;

    /**
    * @brief Returns true if this PathName object holds an relative path
    *
    * @return True if this PathName object holds an relative path
    * (like './foo/bar').
    */
    bool                    relative() const;

    /**
    * @brief Returns the directory part of the path string.
    *
    * Returns the directory part of the path string this PathName object
    * holds. For example:
    *
    * @code
    * std::cout << PathName("/foo/bar/some_file").dirName(); // == "/foo/bar"
    * @endcode
    *
    * @return The substring of the path up to the file name (without
    * prefix)
    */
    PathName                dirName()      const;

    /**
    * @brief Returns the directory part of <b>path</b>
    *
    * Static function to aquire the directory part of a PathName object.
    * For example:
    *
    * @code
    * PathName p1("/foo/bar/some_file");
    * std::cout << PathName::dirName(p1); // == "/foo/bar"
    * @endcode
    *
    * @param path The PathName object you want to inspect
    * @return The substring of the path up to the file name (without prefix)
    */
    static PathName         dirName(const PathName &path);

    /**
    * @brief Returns the base name part of the path string
    *
    * Returns the base name (i.e. the file name) of the path string.
    * For example:
    *
    * @code
    * std::cout << PathName("/foo/bar/some_file").baseName(); // == "some_file"
    * @endcode
    * @return the file name part of the path string
    */
    std::string          baseName()     const;

    /**
    * @brief Returns the base name part of <b>path</b>
    *
    * Returns the base name (i.e. the file name) of the path string.
    * For example:
    *
    * @code
    * PathName p1("/foo/bar/some_file");
    * std::cout << PathName::baseName( p1 ); // == "some_file"
    * @endcode
    *
    * @param path The PathName object you want to inspect
    * @return The file name part of the path string
    */
    static std::string   baseName(const PathName &path);

    /**
    * @brief Returns the absolute name of the path string this object holds.
    *
    * @code
    * PathName p1("foo/bar/some_file");
    * std::cout << p1.absoluteName(); // == "/foo/bar/some_file"
    * @endcode
    *
    * @return The absolute name form of the path string.
    */
    PathName                absoluteName() const;

    /**
    * @brief Returns the absolute name of <b>path</b>.
    *
    * @code
    * PathName p1("foo/bar/some_file");
    * std::cout << absoluteName( p1 ); // == "/foo/bar/some_file"
    * @endcode
    *
    * @return The absolute name form of <b>path</b>.
    */
    static PathName         absoluteName(const PathName &path);

   /**
    * @brief Returns the relative name of the path string this object holds.
    *
    * @code
    * PathName p1("/foo/bar/some_file");
    * std::cout << p1.relativeName(); // == "./foo/bar/some_file"
    * @endcode
    *
    * @return The absolute name form of the path string.
    */
    PathName                relativeName() const;

     /**
    * @brief Returns the relative name of <b>path</b>.
    *
    * @code
    * PathName p1("/foo/bar/some_file");
    * std::cout << relativeName( p1 ); // == "./foo/bar/some_file"
    * @endcode
    *
    * @return The relative name form of <b>path</b>.
    */
    static PathName         relativeName(const PathName &path);

    /**
    * @brief Create a new PathName object from the concatenation of
    * <b>this</b> and <b>add</b>.
    *
    * Creates a new PathName object consisting of the concatenation of
    * this PathName object and <b>add</b> and returns it. For example:
    *
    * @code
    * PathName p1("/foo");
    * PathName p2("bar/some_file");
    * std::cout <<  p1.cat( p2 ); // == "/foo/bar/some_file"
    * @endcode
    *
    * @param add Reference to the PathName object to be added to this
    * object.
    * @return A new PathName object consisting of the concatenation of
    * this object and <b>add</b>.
    */
    PathName                cat(const PathName &add) const;

    /**
    * @brief Create a new PathName object by concatenating two existing
    * ones.
    *
    * Static function for concatenating two PathName objects.
    * For example:
    *
    * @code
    * PathName p1("/foo");
    * PathName p2("bar/some_file");
    * std::cout << PathName::cat( p1, p2 ); // == "/foo/bar/some_file"
    * @endcode
    *
    * @param path The front part of the resulting path.
    * @param add The part that is to be added.
    * @return A PathName object that consists of the concatenation of the
    * two arguments.
    */
    static PathName         cat(const PathName &path,
                                const PathName &add);
    /**
    * @brief Create a new PathName object by extending <b>this</b> PathName
    * object by <b>ext</b>.
    *
    * Use this function to create a new PathName object that consists of
    * <b>this</b> PathName object extended by the string <b>ext</b>. Basically it just
    * glues the two strings together and calls PathName( const std::string )
    * For Example:
    *
    * @code
    * PathName p1("/foo");
    * std::string strExt(".old");
    * std::cout << p1.extend( strExt ); // == "/foo.old"
    * @endcode
    *
    * @param ext Reference to a std::string containing the extension.
    * @return A new PathName object that consists of <b>path</b> extended by
    * <b>ext</b>.
    */
    PathName                extend(const std::string &ext) const;

    /**
    * @brief Create a new PathName object by extending <b>path</b> by
    * <b>ext</b>.
    *
    * Static function to create a new PathName object that consists of
    * <b>path</b> extended by the string <b>ext</b>. Basically it just
    * glues the two strings together and calls PathName( const std::string )
    * For Example:
    *
    * @code
    * PathName p1("/foo");
    * std::string strExt(".old");
    * std::cout << PathName::extend(p1, strExt ); // == "/foo.old"
    * @endcode
    *
    * @param path Reference to a PathName object that is to be extended.
    * @param ext Reference to a std::string containing the extension.
    * @return A new PathName object that consists of <b>path</b> extended by
    * <b>ext</b>.
    */
    static PathName         extend(const PathName       &path,
                                   const std::string &ext);

    /**
    * @brief Test for equality of <b>this</b> and <b>rpath</b>.
    *
    * @param rpath Reference to the PathName object that is to
    * be compared to this object.
    * @return True if path string of <b>rpath</b> equals the path
    * string this object holds.
    */
    bool                    equal(const PathName &rpath) const;

    /**
    * @brief Static function to test for equality of two PathName objects.
    *
    * @param lpath Reference to PathName object one.
    * @param rpath Reference to PathName object two.
    * @return True if <b>lpath</b> equals <b>rpath</b>.
    */
    static bool             equal(const PathName &lpath,
                                  const PathName &rpath);

protected:
    /**
     * @brief Assigns <b>path</b> to this PathName objects m_name string.
     *
     * Takes the given path string, cleans it (i.e.: removing redundant
     * parts from it like './foo/../bar/some_file" -> './bar/some_file')
     * sets m_prefix and assigns the cleansed path string to m_path.
     *
     * @param path path string that is to be assigned to this object.
     * @throws ca_mgm::ValueException
     */

    void                    assign(const std::string &path);

     /**
     * @brief Assigns <b>list</b> to this PathName objects m_name string.
     *
     * Takes the given path list, cleans it (i.e.: removing redundant
     * parts from it like './foo/../bar/some_file" -> './bar/some_file')
     * sets m_prefix and assigns the cleansed path string to m_path.
     *
     * @param path path string that is to be assigned to this object.
     * @throws ca_mgm::ValueException
     */
    void                    assign(const PathName::List &list);

private:
    /**
     * @brief holds index of first character in the path string <b>after</b>
     * an (optional) drive letter.
     */
    size_t          m_prefix;
    std::string  m_name;
};


// -------------------------------------------------------------------
inline bool
operator==(const PathName &lname, const PathName &rname)
{
    return PathName::equal( lname, rname);
}


// -------------------------------------------------------------------
inline bool
operator!=(const PathName &lname, const PathName &rname)
{
    return !PathName::equal( lname, rname);
}


// -------------------------------------------------------------------
inline PathName
operator+ (const PathName &lname, const PathName &rname)
{
    return PathName::cat( lname, rname);
}


// -------------------------------------------------------------------
extern std::ostream &
operator<<(std::ostream &ostr, const PathName &path);


// -------------------------------------------------------------------
}       // End of namespace path
}       // End of namespace LIMAL_NAMESPACE

#endif  // LIMAL_PATH_PATHNAME_HPP
// vim: set ts=8 sts=4 sw=4 ai et:
