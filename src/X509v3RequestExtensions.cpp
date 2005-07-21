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

  File:       X509v3RequestExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/X509v3RequestExtensions.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3RequestExtensions::X509v3RequestExtensions()
{
}

X509v3RequestExtensions::X509v3RequestExtensions(CAConfig* caConfig, Type type)
    : nsSslServerName(caConfig, type),
      nsComment(caConfig, type),
      keyUsage(caConfig, type),
      nsCertType(caConfig, type),
      basicConstraints(caConfig, type),
      extendedKeyUsage(caConfig, type),
      subjectKeyIdentifier(caConfig, type),
      subjectAlternativeName(caConfig, type)
{
}

X509v3RequestExtensions::X509v3RequestExtensions(const X509v3RequestExtensions& extensions)
    : nsSslServerName(extensions.nsSslServerName),
      nsComment(extensions.nsComment),
      keyUsage(extensions.keyUsage),
      nsCertType(extensions.nsCertType),
      basicConstraints(extensions.basicConstraints),
      extendedKeyUsage(extensions.extendedKeyUsage),
      subjectKeyIdentifier(extensions.subjectKeyIdentifier),
      subjectAlternativeName(extensions.subjectAlternativeName)
{
}

X509v3RequestExtensions::~X509v3RequestExtensions()
{}

X509v3RequestExtensions&
X509v3RequestExtensions::operator=(const X509v3RequestExtensions& extensions)
{
    if(this == &extensions) return *this;

    nsSslServerName        = extensions.nsSslServerName;
    nsComment              = extensions.nsComment;
    keyUsage               = extensions.keyUsage;
    nsCertType             = extensions.nsCertType;
    basicConstraints       = extensions.basicConstraints;
    extendedKeyUsage       = extensions.extendedKeyUsage;
    subjectKeyIdentifier   = extensions.subjectKeyIdentifier;
    subjectAlternativeName = extensions.subjectAlternativeName;

    return *this;
}

void
X509v3RequestExtensions::setNsSslServerName(const NsSslServerNameExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setNsSslServerName invalid value");
    }
    nsSslServerName = ext;
}

NsSslServerNameExtension
X509v3RequestExtensions::getNsSslServerName() const
{
    return nsSslServerName;
}

void
X509v3RequestExtensions::setNsComment(const NsCommentExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setNsComment invalid value");
    }
    nsComment = ext;
}

NsCommentExtension
X509v3RequestExtensions::getNsComment() const
{
    return nsComment;
}

void
X509v3RequestExtensions::setNsCertType(const NsCertTypeExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setNsCertType invalid value");
    }
    nsCertType = ext;
}

NsCertTypeExtension
X509v3RequestExtensions::getNsCertType() const
{
    return nsCertType;
}

void
X509v3RequestExtensions::setKeyUsage(const KeyUsageExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setKeyUsage invalid value");
    }
    keyUsage = ext;
}

KeyUsageExtension
X509v3RequestExtensions::getKeyUsage()
{
    return keyUsage;
}

void
X509v3RequestExtensions::setBasicConstraints(const BasicConstraintsExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setBasicConstraints invalid value");
    }
    basicConstraints = ext;
}

BasicConstraintsExtension
X509v3RequestExtensions::getBasicConstraints() const
{
    return basicConstraints;
}

void
X509v3RequestExtensions::setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setExtendedKeyUsage invalid value");
    }
    extendedKeyUsage = ext;
}

ExtendedKeyUsageExtension
X509v3RequestExtensions::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

void
X509v3RequestExtensions::setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setSubjectKeyIdentifier invalid value");
    }
    subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExtension
X509v3RequestExtensions::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

void
X509v3RequestExtensions::setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExtensions::setSubjectAlternativeName invalid value");
    }
    subjectAlternativeName = ext;
}

SubjectAlternativeNameExtension
X509v3RequestExtensions::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}

void
X509v3RequestExtensions::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid X509v3RequestExtensions object");
        BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExtensions object");
    }
    nsSslServerName.commit2Config(ca, type);
    nsComment.commit2Config(ca, type);
    keyUsage.commit2Config(ca, type);
    nsCertType.commit2Config(ca, type);
    basicConstraints.commit2Config(ca, type);
    extendedKeyUsage.commit2Config(ca, type);
    subjectKeyIdentifier.commit2Config(ca, type);
    subjectAlternativeName.commit2Config(ca, type);
}

bool
X509v3RequestExtensions::valid() const
{
    if(!nsSslServerName.valid()) return false;
    if(!nsComment.valid()) return false;
    if(!keyUsage.valid()) return false;
    if(!nsCertType.valid()) return false;
    if(!basicConstraints.valid()) return false;
    if(!extendedKeyUsage.valid()) return false;
    if(!subjectKeyIdentifier.valid()) return false;
    if(!subjectAlternativeName.valid()) return false;
    return true;
}

blocxx::StringArray
X509v3RequestExtensions::verify() const
{
    StringArray result;

    result.appendArray(nsSslServerName.verify());
    result.appendArray(nsComment.verify());
    result.appendArray(keyUsage.verify());  
    result.appendArray(nsCertType.verify());   
    result.appendArray(basicConstraints.verify()); 
    result.appendArray(extendedKeyUsage.verify());
    result.appendArray(subjectKeyIdentifier.verify());
    result.appendArray(subjectAlternativeName.verify());

    LOGIT_DEBUG_STRINGARRAY("X509v3RequestExtensions::verify()", result);
    return result;
}

blocxx::StringArray
X509v3RequestExtensions::dump() const
{
    StringArray result;
    result.append("X509v3RequestExtensions::dump()");

    result.appendArray(nsSslServerName.dump());
    result.appendArray(nsComment.dump());
    result.appendArray(keyUsage.dump());  
    result.appendArray(nsCertType.dump());   
    result.appendArray(basicConstraints.dump()); 
    result.appendArray(extendedKeyUsage.dump());
    result.appendArray(subjectKeyIdentifier.dump());
    result.appendArray(subjectAlternativeName.dump());

    return result;
}
