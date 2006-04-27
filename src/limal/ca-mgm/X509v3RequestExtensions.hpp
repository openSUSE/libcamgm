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
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;
	class X509v3RequestExtsImpl;
	
    /**
     * @brief Collection of X509v3 extension for certificate requests
     *
     * This class includes a collection of X509v3 extension for 
     * certificate requests.
     */
    class X509v3RequestExts {

    public:
        X509v3RequestExts();
        X509v3RequestExts(CAConfig* caConfig, Type type);
        X509v3RequestExts(const X509v3RequestExts& extensions);
        virtual ~X509v3RequestExts();

#ifndef SWIG

    	X509v3RequestExts&
        operator=(const X509v3RequestExts& extensions);

#endif
    	
        void
        setNsSslServerName(const NsSslServerNameExt &ext);
        
        NsSslServerNameExt
        getNsSslServerName() const;

        void
        setNsComment(const NsCommentExt &ext);
        
        NsCommentExt
        getNsComment() const;

        void
        setNsCertType(const NsCertTypeExt &ext);
        
        NsCertTypeExt
        getNsCertType() const;

        void
        setKeyUsage(const KeyUsageExt &ext);
        
        KeyUsageExt
        getKeyUsage();

        void
        setBasicConstraints(const BasicConstraintsExt &ext);
        
        BasicConstraintsExt
        getBasicConstraints() const;

        void
        setExtendedKeyUsage(const ExtendedKeyUsageExt &ext);
        
        ExtendedKeyUsageExt
        getExtendedKeyUsage() const;

        void
        setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext);
        
        SubjectKeyIdentifierExt
        getSubjectKeyIdentifier() const;

        void
        setSubjectAlternativeName(const SubjectAlternativeNameExt &ext);
        
        SubjectAlternativeNameExt
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
    	blocxx::COWIntrusiveReference<X509v3RequestExtsImpl> m_impl;

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_REQUEST_EXTENSIONS_HPP
