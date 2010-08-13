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

  File:       PathName.cpp

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

   File:       PathName.cc

   Author:     Michael Andres <ma@suse.de>
   Maintainer: Michael Andres <ma@suse.de>

/-*/

#include <limal/PathName.hpp>
#include <limal/Exception.hpp>
#include <limal/String.hpp>

#include "Utils.hpp"
#include <iostream>

extern "C"
{
    #include <sys/types.h>
    #include <unistd.h>
    #include <pwd.h>
}


// -------------------------------------------------------------------
namespace LIMAL_NAMESPACE
{
namespace path
{


// -------------------------------------------------------------------
// anonymous namespace
namespace
{
    size_t
    findTildeEnd(const std::string &name)
    {
        const char *beg, *end;

        beg = end = name.c_str();
        do
        {
            switch( *end)
            {
                case '/':
                case '\\':
                return end - beg;
            }
        } while( *end++);
        return std::string::npos;
    }

    std::string
    expandTilde(const std::string &name)
    {
        if( name.compare(0, 1, "~") == 0)
        {
            std::string user;
            std::string home;
            std::string rest;
            size_t end = findTildeEnd(name);

            user = name.substr(1, end);
            rest = name.substr(end);

            if( user.empty())
            {
                if( ::getuid() != ::geteuid())
                {
                    home = getenv("HOME");

                    if( home.compare(0, 1, "~") == 0)
                        home = "";
                }

                if( home.empty())
                {
                    ::setpwent();
                    struct passwd *pw = ::getpwuid(::getuid());
                    if( pw)
                    {
                        home = pw->pw_dir;
                    }
                    ::endpwent();
                }
            }
            else if(('a' <= user[0] && user[0] <= 'z') ||
                    ('A' <= user[0] && user[0] <= 'Z'))
            {
                ::setpwent();
                struct passwd *pw = ::getpwnam(user.c_str());
                if( pw)
                {
                    home = pw->pw_dir;
                }
                ::endpwent();
            }

            if( !home.empty())
            {
                return home + "/" + rest;
            }
        }
        return name;
    }

    inline size_t
    withDrivePrefix(const std::string &name)
    {
        size_t len = name.length();

        return (len >= 2 && name[1] == ':' &&
                (('a' <= name[0] && name[0] <= 'z') ||
                ('A' <= name[0] && name[0] <= 'Z'))) ? len : 0;
    }

    class DirStack
    {
    private:
        bool           m_first;
        PathName::List m_list;

    public:
        DirStack()
            : m_first(true)
        {}

        DirStack(const DirStack &list)
            : m_first(list.m_first)
            , m_list(list.m_list)
        {
        }

        ~DirStack()
        {}

        void
        push(PathName::List::const_iterator first,
             PathName::List::const_iterator last)
        {
            for( ; first != last; ++first)
            {
                if( *first == "/" || *first == "\\")
                    push("");
                else
                    push( *first);
            }
        }

        void
        push(const std::string &name)
        {
            if( name.find_first_of('/')  != std::string::npos ||
                name.find_first_of('\\') != std::string::npos)
            {
                CA_MGM_THROW(ca_mgm::ValueException,
                    str::form(__("The specified filename component '%s' "
                              "contains a filename separator"),
                           name.c_str()).c_str()
                );
            }

            if( name.empty() || name == ".")
            {
                // '.' or '/' only if first one
                if( !m_first)
                    return;
            }
            else
            if( name == ".." && !m_list.empty())
            {
                if( m_list.front() == "" && m_list.size() == 1)
                {
                    // "/.."        ==> "/"
                    return;
                }
                if(  m_list.back() != "." &&
                     m_list.back() != ".." )
                {
                    // "somedir/.." ==> ""
                    m_list.pop_back();
                    return;
                }

                // "../.." and "./.." stays
            }
            else
            if( m_list.empty())
            {
                // prepend "." to relative paths
                m_list.push_back(".");
            }

            m_first = false;
            m_list.push_back( name);
        }

        void
        split(const std::string &path)
        {
            const char *beg, *end;

            beg = end = path.c_str();
            do
            {
                switch ( *end)
                {
                    case '/':
                    case '\\':
                    case '\0':
                        if( end > beg)
                            push(std::string(beg, end - beg));
                        else
                            push("");
                        beg = end + 1;
                    break;
                }
            } while( *end++);
        }

        PathName::List
        getPathList() const
        {
            return m_list;
        }

        std::string
        getPathName(const std::string &sep = FILENAME_SEPARATOR) const
        {
            if( m_first)
                return "";

            std::string path;
            PathName::List::const_iterator i(m_list.begin());
            for( ; i != m_list.end(); ++i)
            {
                if( i != m_list.begin())
                    path += sep;
                path += *i;
            }

            if( path.empty())
                return sep;
            else
                return path;
        }
    };

}   // End of anonymous namespace


// -------------------------------------------------------------------
// --- PathName ------------------------------------------------------
// -------------------------------------------------------------------
PathName::PathName()
    : m_prefix(0)
{
}


// -------------------------------------------------------------------
PathName::PathName(const PathName &path)
    : m_prefix(path.m_prefix)
    , m_name(path.m_name)
{
}


// -------------------------------------------------------------------
PathName::PathName(const PathName::List &list)
    : m_prefix(0)
{
    assign( list);
}


// -------------------------------------------------------------------
PathName::PathName(const std::string &name)
    : m_prefix(0)
{
    assign( name);
}


// -------------------------------------------------------------------
PathName::PathName(const char *name)
    : m_prefix(0)
{
    assign( name ? name : "");
}


// -------------------------------------------------------------------
PathName::~PathName()
{
}


// -------------------------------------------------------------------
void
PathName::assign(const PathName::List &list)
{
    m_prefix = 0;
    m_name = "";

    if( list.empty())
        return;

    PathName::List::const_iterator item(list.begin());

    std::string drive;
    size_t prefix = withDrivePrefix(*item);

    if( prefix)
    {
        if( prefix != 2)
        {
            CA_MGM_THROW(ca_mgm::ValueException,
            __("Invalid drive letter prefix in the specified path list."));
        }
        drive = *item;
    }
    else
    if( !item->empty() )
    {
        CA_MGM_THROW(ca_mgm::ValueException,
            __("The first pathname list component has to be "
               "empty or contain a drive letter prefix")
        );
    }
    item++;

    DirStack stack;
    try
    {
        stack.push(item, list.end());
    }
    catch(const ca_mgm::ValueException &e)
    {
        CA_MGM_THROW_SUBEX(ca_mgm::ValueException,
            __("The path list contains an element with a filename separator."),
            e);
    }

    m_name = drive + stack.getPathName();
    m_prefix = prefix;
}


// -------------------------------------------------------------------
void
PathName::assign(const std::string &name)
{
    m_prefix = 0;
    m_name   = "";

    if ( name.empty())
        return;

    std::string drive;
    std::string path(name);
    size_t prefix = 0;

    if( withDrivePrefix(path))
    {
        prefix = 2;
        drive  = path.substr(0, 2);
    }
    else
    {
        path = expandTilde(path);
        if( withDrivePrefix(path))
        {
            prefix = 2;
            drive  = path.substr(0, 2);
        }
    }

    DirStack stack;
    stack.split(path.c_str() + prefix);

    m_name = drive + stack.getPathName();
    m_prefix = prefix;
}


// -------------------------------------------------------------------
std::string
PathName::toString() const
{
    return m_name;
}


// -------------------------------------------------------------------
PathName::List
PathName::toList() const
{
    PathName::List list;
    if( m_name.empty())
        return list;

    list.push_back( prefix() );

    DirStack stack;

    stack.split(m_name.c_str() + m_prefix);
    PathName::List temp( stack.getPathList() );
    list.insert( list.end(), temp.begin(), temp.end() );
    return list;
}


// -------------------------------------------------------------------
std::string
PathName::prefix() const
{
    return m_name.empty() ? "" : m_name.substr(0, m_prefix);
}


// -------------------------------------------------------------------
bool
PathName::empty() const
{
    return m_name.empty();
}


// -------------------------------------------------------------------
bool
PathName::absolute() const
{
    return !m_name.empty() && (m_name[m_prefix] == '/' ||
                               m_name[m_prefix] == '\\');
}


// -------------------------------------------------------------------
bool
PathName::relative() const
{
    return !m_name.empty() && (m_name[m_prefix] != '/' &&
                               m_name[m_prefix] != '\\');
}


// -------------------------------------------------------------------
PathName
PathName::dirName() const
{
    return dirName( *this);
}


// -------------------------------------------------------------------
std::string
PathName::baseName() const
{
    return baseName( *this);
}


// -------------------------------------------------------------------
PathName
PathName::absoluteName() const
{
    return absoluteName( *this);
}


// -------------------------------------------------------------------
PathName
PathName::relativeName() const
{
    return relativeName( *this );
}


// -------------------------------------------------------------------
// STATIC
PathName
PathName::dirName(const PathName &name)
{
    if ( name.empty())
        return "";

    PathName ret( name);

    size_t idx = ret.m_name.find_last_of( FILENAME_SEPARATOR_C);
    if ( idx == std::string::npos)
    {
        ret.m_name.erase( ret.m_prefix);
        ret.m_name += ".";
    }
    else if ( idx == ret.m_prefix )
    {
        ret.m_name.erase( ret.m_prefix);
        ret.m_name += FILENAME_SEPARATOR;
    }
    else
    {
        ret.m_name.erase( idx);
    }

    return ret;
}


// -------------------------------------------------------------------
// STATIC
std::string
PathName::baseName(const PathName &name)
{
    if ( name.empty() )
        return "";

    std::string ret( name.toString());
    ret.erase( 0, name.m_prefix);

    size_t idx = ret.find_last_of( FILENAME_SEPARATOR_C);
    if ( idx != std::string::npos)
    {
        ret.erase( 0, idx + 1);
    }

    return ret;
}


// -------------------------------------------------------------------
// STATIC
PathName
PathName::absoluteName(const PathName &name)
{
    return name.relative() ? cat( FILENAME_SEPARATOR, name) : name;
}


// -------------------------------------------------------------------
// STATIC
PathName
PathName::relativeName(const PathName &name)
{
    return name.absolute() ? cat( ".", name) : name;
}


// -------------------------------------------------------------------
PathName
PathName::cat(const PathName &add) const
{
    return cat( *this, add);
}


// -------------------------------------------------------------------
PathName
PathName::extend(const std::string &ext) const
{
    return extend( *this, ext);
}


// -------------------------------------------------------------------
bool
PathName::equal(const PathName &rname) const
{
    return equal( *this, rname);
}


// -------------------------------------------------------------------
// STATIC
PathName
PathName::cat(const PathName &name, const PathName &add)
{
    if ( add.empty())
        return name;

    if ( name.empty())
        return add;

    std::string ret = FILENAME_SEPARATOR +
                 add.toString().substr(add.m_prefix) ;

    return PathName(name.toString() + ret);
}


// -------------------------------------------------------------------
// STATIC
PathName
PathName::extend(const PathName &name, const std::string &ext)
{
    return PathName(name.toString() + ext);
}


// -------------------------------------------------------------------
// STATIC
bool
PathName::equal(const PathName &lname, const PathName &rname)
{
    return lname.toString() == rname.toString();
}


// -------------------------------------------------------------------
PathName &
PathName::operator= (const PathName &path)
{
    if ( &path != this)
    {
        m_prefix = path.m_prefix;
        m_name   = path.m_name;
    }
    return *this;
}


// -------------------------------------------------------------------
PathName &
PathName::operator+=(const PathName &path)
{
    return (*this = cat( *this, path));
}

// -------------------------------------------------------------------
std::ostream & operator<< (std::ostream &ostr, const PathName &path)
{
    ostr << path.toString();
    return ostr;
}


// -------------------------------------------------------------------
}       // End of namespace path
}       // End of namespace LIMAL_NAMESPACE
// vim: set ts=8 sts=4 sw=4 ai et:
