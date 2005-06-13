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

  File:       RequestGenerationData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/RequestGenerationData.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RequestGenerationData::RequestGenerationData()
{
}

RequestGenerationData::RequestGenerationData(CA& ca, Type type)
{
}

RequestGenerationData::RequestGenerationData(const RequestGenerationData& data)
{
}

RequestGenerationData::~RequestGenerationData()
{
}

RequestGenerationData&
RequestGenerationData::operator=(const RequestGenerationData& data)
{
    return *this;
}

void
RequestGenerationData::setSubject(const DNObject dn)
{
    subject = dn;
}

DNObject
RequestGenerationData::getSubject() const
{
    return subject;
}

void
RequestGenerationData::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

blocxx::UInt32
RequestGenerationData::getKeysize() const
{
    return keysize;
}

void
RequestGenerationData::setChallengePassword(const String &passwd)
{
    challengePassword = passwd;
}

blocxx::String
RequestGenerationData::getChallengePassword() const
{
    return challengePassword;
}

void
RequestGenerationData::setUnstructuredName(const String &name)
{
    unstructuredName = name;
}

blocxx::String
RequestGenerationData::getUnstructuredName() const
{
    return unstructuredName;
}

void
RequestGenerationData::setExtensions(const X509v3RequestExtensions &ext)
{
    extensions = ext;
}

X509v3RequestExtensions
RequestGenerationData::getExtensions() const
{
    return extensions;
}

void
RequestGenerationData::commit2Config(CA& ca, Type type)
{
}

