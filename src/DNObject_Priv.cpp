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

  File:       DNObject_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "DNObject_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

DNObject_Int::DNObject_Int(X509* cert)
    : DNObject()
{
}

DNObject_Int::~DNObject_Int()
{
}

//  private:
DNObject_Int::DNObject_Int(const DNObject_Int& obj)
    : DNObject(obj)
{
}

DNObject_Int&
DNObject_Int::operator=(const DNObject_Int& obj)
{
    return *this;
}
