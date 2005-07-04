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

  File:       X509v3RequestExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "X509v3RequestExtensions_Priv.hpp"
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3RequestExtensions_Priv::X509v3RequestExtensions_Priv()
    : X509v3RequestExtensions()
{
}

X509v3RequestExtensions_Priv::X509v3RequestExtensions_Priv(X509_REQ* req)
    : X509v3RequestExtensions()
{
}

X509v3RequestExtensions_Priv::~X509v3RequestExtensions_Priv()
{
}


//    private:
X509v3RequestExtensions_Priv::X509v3RequestExtensions_Priv(const X509v3RequestExtensions_Priv& extensions)
    : X509v3RequestExtensions(extensions)
{
}

X509v3RequestExtensions_Priv&
X509v3RequestExtensions_Priv::operator=(const X509v3RequestExtensions_Priv& extensions)
{
    if(this == &extensions) return *this;
    
    X509v3RequestExtensions::operator=(extensions);

    return *this;
}
