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

  File:       X509v3RequestExtensions_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "X509v3RequestExtensions_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3RequestExtensions_Int::X509v3RequestExtensions_Int()
    : X509v3RequestExtensions()
{
}

X509v3RequestExtensions_Int::X509v3RequestExtensions_Int(X509_REQ* req)
    : X509v3RequestExtensions()
{
}

X509v3RequestExtensions_Int::~X509v3RequestExtensions_Int()
{
}


//    private:
X509v3RequestExtensions_Int::X509v3RequestExtensions_Int(const X509v3RequestExtensions_Int& extensions)
    : X509v3RequestExtensions(extensions)
{
}

X509v3RequestExtensions_Int&
X509v3RequestExtensions_Int::operator=(const X509v3RequestExtensions_Int& extensions)
{
    return *this;
}
