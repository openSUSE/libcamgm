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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RequestGenerationData::RequestGenerationData()
    : subject(DNObject()),
      keysize(0),
      messageDigest(SHA1),
      challengePassword(""),
      unstructuredName(""),
      extensions(X509v3RequestExtensions())
{
}

RequestGenerationData::RequestGenerationData(CAConfig* caConfig, Type type)
    : subject(DNObject()),
      keysize(0),
      messageDigest(SHA1),
      challengePassword(""),
      unstructuredName(""),
      extensions(X509v3RequestExtensions(caConfig, type))
{
    keysize = caConfig->getValue(type2Section(type, false), "default_bits").toUInt32();

    String md = caConfig->getValue(type2Section(type, false), "default_md");
    if(md.equalsIgnoreCase("sha1")) {
        messageDigest = SHA1;
    } else if(md.equalsIgnoreCase("md5")) {
        messageDigest = MD5;
    } else if(md.equalsIgnoreCase("mdc2")) {
        messageDigest = MDC2;
    } else {
        LOGIT_INFO("unsupported message digest: " << md);
        LOGIT_INFO("select default sha1.");
        messageDigest = SHA1;
    }
}

RequestGenerationData::RequestGenerationData(const RequestGenerationData& data)
    : subject(data.subject),
      keysize(data.keysize),
      messageDigest(data.messageDigest),
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
    messageDigest     = data.messageDigest;
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
RequestGenerationData::setMessageDigest(MD md)
{
    messageDigest = md;
}

MD 
RequestGenerationData::getMessageDigest() const
{
    return messageDigest;
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
RequestGenerationData::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid RequestGenerationData object");
        BLOCXX_THROW(limal::ValueException, "invalid RequestGenerationData object");
    }

    if(type == CRL || type == Client_Cert ||
       type == Server_Cert || type == CA_Cert ) {

        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    ca.getConfig()->setValue(type2Section(type, false), "default_bits", String(keysize));

    String md("sha1");
    switch(messageDigest) {
    case SHA1:
        md = "sha1";
        break;
    case MD5:
        md = "md5";
        break;
    case MDC2:
        md = "mdc2";
        break;
    }
    ca.getConfig()->setValue(type2Section(type, false), "default_md", md);

    extensions.commit2Config(ca, type);
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

blocxx::StringArray
RequestGenerationData::dump() const
{
    StringArray result;
    result.append("RequestGenerationData::dump()");

    result.appendArray(subject.dump());
    result.append("Keysize = " + String(keysize));
    result.append("MessageDigest = " + String(messageDigest));
    result.append("Challenge Password = " + challengePassword);
    result.append("Unstructured Name = " + unstructuredName);
    result.appendArray(extensions.dump());

    return result;
}
