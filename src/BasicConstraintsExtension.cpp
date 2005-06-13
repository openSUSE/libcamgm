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

  File:       BasicConstraintsExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

BasicConstraintsExtension::BasicConstraintsExtension()
    : ExtensionBase()
{

}

BasicConstraintsExtension::BasicConstraintsExtension(CA& ca, Type type)
    : ExtensionBase()
{

}

BasicConstraintsExtension::BasicConstraintsExtension(bool isCa, blocxx::Int32 pathLength)
    : ExtensionBase()
{

}

BasicConstraintsExtension::BasicConstraintsExtension(const BasicConstraintsExtension& extension)
    : ExtensionBase()
{

}

BasicConstraintsExtension::~BasicConstraintsExtension()
{

}


BasicConstraintsExtension&
BasicConstraintsExtension::operator=(const BasicConstraintsExtension& extension)
{
    return *this;
}

void
BasicConstraintsExtension::setCA(bool isCa)
{

}

bool
BasicConstraintsExtension::isCA() const
{
    return ca;
}

void
BasicConstraintsExtension::setPathLength(blocxx::Int32 pathLength)
{

}

blocxx::Int32
BasicConstraintsExtension::getPathLength() const
{
    return pathlen;
}

void
BasicConstraintsExtension::commit2Config(CA& ca, Type type)
{
}
