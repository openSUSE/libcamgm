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
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RequestGenerationData::RequestGenerationData()
    : subject(DNObject()),
      keysize(0),
      challengePassword(""),
      unstructuredName(""),
      extensions(X509v3RequestExtensions())
{
}

RequestGenerationData::RequestGenerationData(CA& ca, Type type)
    : subject(DNObject()),
      keysize(0),
      challengePassword(""),
      unstructuredName(""),
      extensions(X509v3RequestExtensions())
{
}

RequestGenerationData::RequestGenerationData(const RequestGenerationData& data)
    : subject(data.subject),
      keysize(data.keysize),
      challengePassword(data.challengePassword),
      unstructuredName(data.unstructuredName),
      extensions(data.extensions)
{}

RequestGenerationData::~RequestGenerationData()
{
}

RequestGenerationData&
RequestGenerationData::operator=(const RequestGenerationData& data)
{
    if(this == &data) return *this;

    subject           = data.subject;
    keysize           = data.keysize;
    challengePassword = data.challengePassword;
    unstructuredName  = data.unstructuredName;
    extensions        = data.extensions;

    return *this;
}

void
RequestGenerationData::setSubject(const DNObject dn)
{
    StringArray r = dn.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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

bool
RequestGenerationData::valid() const
{
    if(!subject.valid()) return false;

    // keysize??

    return extensions.valid();
}

blocxx::StringArray
RequestGenerationData::verify() const
{
    StringArray result;

    result.appendArray(subject.verify());

    // keysize??

    result.appendArray(extensions.verify());

    LOGIT_DEBUG_STRINGARRAY("RequestGenerationData::verify()", result);

    return result;
}
