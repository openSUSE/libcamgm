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

  File:       CRLGenerationData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CRLGenerationData.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLGenerationData::CRLGenerationData()
{
}

CRLGenerationData::CRLGenerationData(CA& ca, Type type)
{
}

CRLGenerationData::CRLGenerationData(blocxx::UInt32 hours, 
                                     const X509v3CRLGenerationExtensions& ext)
{
}

CRLGenerationData::CRLGenerationData(const CRLGenerationData& data)
{
}

CRLGenerationData::~CRLGenerationData()
{
}
       
CRLGenerationData&
CRLGenerationData::operator=(const CRLGenerationData& data)
{
    return *this;
}

void
CRLGenerationData::setCRLLifeTime(blocxx::UInt32 hours)
{
    crlHours = hours;
}

blocxx::UInt32
CRLGenerationData::getCRLLifeTime() const
{
    return crlHours;
}

void
CRLGenerationData::setExtensions(const X509v3CRLGenerationExtensions& ext)
{
    extensions = ext;
}

X509v3CRLGenerationExtensions
CRLGenerationData::getExtensions() const
{
    return extensions;
}

void
CRLGenerationData::commit2Config(CA& ca, Type type)
{
}


