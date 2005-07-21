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

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    class BasicConstraintsExtension : public ExtensionBase {
    public:
        BasicConstraintsExtension();
        BasicConstraintsExtension(CAConfig* caConfig, Type type);
        BasicConstraintsExtension(bool isCa, blocxx::Int32 pathLength=-1);
        BasicConstraintsExtension(const BasicConstraintsExtension& extension);
        virtual ~BasicConstraintsExtension();

        BasicConstraintsExtension& operator=(const BasicConstraintsExtension& extension);

        void           setBasicConstraints(bool isCa, blocxx::Int32 pathLength=-1);

        bool           isCA() const;
        blocxx::Int32  getPathLength() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;  
        virtual blocxx::StringArray  verify() const; 

        virtual blocxx::StringArray  dump() const;

    private:
        bool           ca;
        blocxx::Int32  pathlen;
    };

}
}

#endif // LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
