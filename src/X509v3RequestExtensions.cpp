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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3RequestExtensions::X509v3RequestExtensions()
{
}

X509v3RequestExtensions::X509v3RequestExtensions(CA& ca, Type type)
{
}

X509v3RequestExtensions::X509v3RequestExtensions(const X509v3RequestExtensions& extensions)
{
}

X509v3RequestExtensions::~X509v3RequestExtensions()
{
}

X509v3RequestExtensions&
X509v3RequestExtensions::operator=(const X509v3RequestExtensions& extensions)
{
    return *this;
}

void
X509v3RequestExtensions::setNsSslServerName(const NsSslServerNameExtension &ext)
{
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
    subjectAlternativeName = ext;
}

SubjectAlternativeNameExtension
X509v3RequestExtensions::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}

void
X509v3RequestExtensions::commit2Config(CA& ca, Type type)
{
}

