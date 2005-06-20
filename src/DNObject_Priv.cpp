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

  File:       DNObject_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "DNObject_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

DNObject_Priv::DNObject_Priv(X509* cert)
    : DNObject()
{
}

DNObject_Priv::~DNObject_Priv()
{
}

//  private:
DNObject_Priv::DNObject_Priv(const DNObject_Priv& obj)
    : DNObject(obj)
{
}

DNObject_Priv&
DNObject_Priv::operator=(const DNObject_Priv& obj)
{
    return *this;
}
