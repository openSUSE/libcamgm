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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

ExtensionBase::ExtensionBase(const ExtensionBase& extension)
    : present(extension.present), critical(extension.critical)
{}

ExtensionBase::~ExtensionBase()
{}

ExtensionBase&
ExtensionBase::operator=(const ExtensionBase& extension)
{

}

void   
ExtensionBase::setPresent(bool extPresent)
{
    present = extPresent;
}

void   
ExtensionBase::setCritical(bool extCritical)
{
    setPresent(true);
    critical = extCritical;
}

