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

  File:       X509v3RequestExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/ExtendedKeyUsageExt.hpp>
#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    /**
     * @brief Collection of X509v3 extension for certificate requests
     *
     * This class includes a collection of X509v3 extension for 
     * certificate requests.
     */
    class X509v3RequestExtensions {

    public:
        X509v3RequestExtensions();
        X509v3RequestExtensions(CAConfig* caConfig, Type type);
        X509v3RequestExtensions(const X509v3RequestExtensions& extensions);
        virtual ~X509v3RequestExtensions();

        X509v3RequestExtensions&
        operator=(const X509v3RequestExtensions& extensions);

        void
        setNsSslServerName(const NsSslServerNameExtension &ext);
        
        NsSslServerNameExtension
        getNsSslServerName() const;

        void
        setNsComment(const NsCommentExtension &ext);
        
        NsCommentExtension
        getNsComment() const;

        void
        setNsCertType(const NsCertTypeExtension &ext);
        
        NsCertTypeExtension
        getNsCertType() const;

        void
        setKeyUsage(const KeyUsageExtension &ext);
        
        KeyUsageExtension
        getKeyUsage();

        void
        setBasicConstraints(const BasicConstraintsExtension &ext);
        
        BasicConstraintsExtension
        getBasicConstraints() const;

        void
        setExtendedKeyUsage(const ExtendedKeyUsageExt &ext);
        
        ExtendedKeyUsageExt
        getExtendedKeyUsage() const;

        void
        setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext);
        
        SubjectKeyIdentifierExtension
        getSubjectKeyIdentifier() const;

        void
        setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext);
        
        SubjectAlternativeNameExtension
        getSubjectAlternativeName() const;

        void
        commit2Config(CA& ca, Type type) const;

        virtual bool
        valid() const;
        
        virtual blocxx::StringArray
        verify() const;

        virtual blocxx::StringArray
        dump() const;

    protected:

        /* String extensions */

        NsSslServerNameExtension        nsSslServerName;
        NsCommentExtension              nsComment;

        /* Bit Strings */
        KeyUsageExtension               keyUsage; 
        NsCertTypeExtension             nsCertType;

        BasicConstraintsExtension       basicConstraints;
        ExtendedKeyUsageExt             extendedKeyUsage;
        SubjectKeyIdentifierExtension   subjectKeyIdentifier;
        SubjectAlternativeNameExtension subjectAlternativeName;

        // AuthorityInfoAccessExtension    authorityInfoAccess;  // ???

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP
