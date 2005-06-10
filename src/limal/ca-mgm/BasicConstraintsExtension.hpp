/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                           |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       BasicConstraintsExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
#define    LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/CA.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class BasicConstraintsExtension : public ExtensionBase {
    public:
        BasicConstraintsExtension();
        BasicConstraintsExtension(CA& ca, Type type);
        BasicConstraintsExtension(bool isCa, blocxx::Int32 pathLength=-1);
        BasicConstraintsExtension(const BasicConstraintsExtension& extension);
        virtual ~BasicConstraintsExtension();

        BasicConstraintsExtension& operator=(const BasicConstraintsExtension& extension);

        void           setCA(bool isCa);
        bool           isCA() const;

        void           setPathLength(blocxx::Int32 pathLength);
        blocxx::Int32  getPathLength() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        bool           ca;
        blocxx::Int32  pathlen;
    };

}
}

#endif // LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
