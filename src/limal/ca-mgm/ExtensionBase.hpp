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

  File:       ExtensionBase.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_EXTENSION_BASE_HPP
#define    LIMAL_CA_MGM_EXTENSION_BASE_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class ExtensionBase {

    public:
        ExtensionBase(bool extPresent = false, bool extCritical = false);

        ExtensionBase(const ExtensionBase& extension);

        virtual ~ExtensionBase();

        ExtensionBase& operator=(const ExtensionBase& extension);

        void   setPresent(bool extPresent);
        void   setCritical(bool extCritical);

        bool   isCritical() const { return (present)?critical:false; }
        bool   isPresent() const  { return present; }

        virtual void commit2Config(CA& ca, Type type) = 0;

        virtual bool                 valid() const =0;
        virtual blocxx::StringArray  verify() const =0;

    private:
        bool present;
        bool critical;
    };

}
}

#endif // LIMAL_CA_MGM_EXTENSION_BASE_HPP
