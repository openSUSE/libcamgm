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

  File:       ExtensionBase.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/ExtensionBase.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

ExtensionBase::ExtensionBase(bool extPresent, bool extCritical)
    :present(extPresent), critical(extCritical) 
{
}

ExtensionBase::ExtensionBase(const ExtensionBase& extension)
    : present(extension.present), critical(extension.critical)
{}

ExtensionBase::~ExtensionBase()
{}

ExtensionBase&
ExtensionBase::operator=(const ExtensionBase& extension)
{
    if(this == &extension) return *this;

    present   = extension.present;
    critical  = extension.critical;

    return *this;
}

void   
ExtensionBase::setPresent(bool extPresent)
{
    LOGIT_DEBUG("ExtensionBase::setPresent(): " << (extPresent ? "true":"false") );
    present = extPresent;
}

void   
ExtensionBase::setCritical(bool extCritical)
{
    LOGIT_DEBUG("ExtensionBase::setCritical(): " << (extCritical ? "true":"false") );
    setPresent(true);
    critical = extCritical;
}
