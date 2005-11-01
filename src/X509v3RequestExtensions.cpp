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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

X509v3RequestExts::X509v3RequestExts()
{
}

X509v3RequestExts::X509v3RequestExts(CAConfig* caConfig, Type type)
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

X509v3RequestExts::X509v3RequestExts(const X509v3RequestExts& extensions)
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

X509v3RequestExts::~X509v3RequestExts()
{}

X509v3RequestExts&
X509v3RequestExts::operator=(const X509v3RequestExts& extensions)
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
X509v3RequestExts::setNsSslServerName(const NsSslServerNameExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setNsSslServerName invalid value");
    }
    nsSslServerName = ext;
}

NsSslServerNameExt
X509v3RequestExts::getNsSslServerName() const
{
    return nsSslServerName;
}

void
X509v3RequestExts::setNsComment(const NsCommentExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setNsComment invalid value");
    }
    nsComment = ext;
}

NsCommentExt
X509v3RequestExts::getNsComment() const
{
    return nsComment;
}

void
X509v3RequestExts::setNsCertType(const NsCertTypeExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setNsCertType invalid value");
    }
    nsCertType = ext;
}

NsCertTypeExt
X509v3RequestExts::getNsCertType() const
{
    return nsCertType;
}

void
X509v3RequestExts::setKeyUsage(const KeyUsageExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setKeyUsage invalid value");
    }
    keyUsage = ext;
}

KeyUsageExt
X509v3RequestExts::getKeyUsage()
{
    return keyUsage;
}

void
X509v3RequestExts::setBasicConstraints(const BasicConstraintsExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setBasicConstraints invalid value");
    }
    basicConstraints = ext;
}

BasicConstraintsExt
X509v3RequestExts::getBasicConstraints() const
{
    return basicConstraints;
}

void
X509v3RequestExts::setExtendedKeyUsage(const ExtendedKeyUsageExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setExtendedKeyUsage invalid value");
    }
    extendedKeyUsage = ext;
}

ExtendedKeyUsageExt
X509v3RequestExts::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

void
X509v3RequestExts::setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setSubjectKeyIdentifier invalid value");
    }
    subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExt
X509v3RequestExts::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

void
X509v3RequestExts::setSubjectAlternativeName(const SubjectAlternativeNameExt &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3RequestExts::setSubjectAlternativeName invalid value");
    }
    subjectAlternativeName = ext;
}

SubjectAlternativeNameExt
X509v3RequestExts::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}

void
X509v3RequestExts::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid X509v3RequestExts object");
        BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExts object");
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
X509v3RequestExts::valid() const
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
X509v3RequestExts::verify() const
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

    LOGIT_DEBUG_STRINGARRAY("X509v3RequestExts::verify()", result);
    return result;
}

blocxx::StringArray
X509v3RequestExts::dump() const
{
    StringArray result;
    result.append("X509v3RequestExts::dump()");

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

}
}
