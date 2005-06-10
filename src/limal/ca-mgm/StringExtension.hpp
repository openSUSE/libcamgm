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

  File:       StringExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_STRING_EXTENSION_HPP
#define    LIMAL_CA_MGM_STRING_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/CA.hpp>

namespace LIMAL_NAMESPACE {
    
namespace CA_MGM_NAMESPACE {
    
    class StringExtension : public ExtensionBase {
        
    public:
        virtual ~StringExtension();

        virtual void   setValue(const String &v) = 0;
        virtual void   getValue() const = 0;
        
        virtual void commit2Config(CA& ca, Type type) = 0;
        
    protected:
        StringExtension(const String &v ) : value(v) {};
        StringExtension(const StringExtension& extension);
        
        StringExtension& operator=(const StringExtension& extension);
        
    private:
        String value;
        
        StringExtension();
    };

    class NsBaseUrlExtension : public StringExtension { 
    public:
        NsBaseUrlExtension(const String &v);
        NsBaseUrlExtension(CA& ca, Type type);
        NsBaseUrlExtension(const NsBaseUrlExtension &extension);
        virtual ~NsBaseUrlExtension();

        NsBaseUrlExtension& operator=(const NsBaseUrlExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsBaseUrlExtension();
    };

    class NsRevocationUrlExtension : public StringExtension { 
    public:
        NsRevocationUrlExtension(const String &v);
        NsRevocationUrlExtension(CA& ca, Type type);
        NsRevocationUrlExtension(const NsRevocationUrlExtension &extension);
        virtual ~NsRevocationUrlExtension();

        NsRevocationUrlExtension& operator=(const NsRevocationUrlExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsRevocationUrlExtension();

    };

    class NsCaRevocationUrlExtension : public StringExtension { 
    public:
        NsCaRevocationUrlExtension(const String &v);
        NsCaRevocationUrlExtension(CA& ca, Type type);
        NsCaRevocationUrlExtension(const NsCaRevocationUrlExtension &extension);
        virtual ~NsCaRevocationUrlExtension();

        NsCaRevocationUrlExtension& operator=(const NsCaRevocationUrlExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsCaRevocationUrlExtension();

    };

    class NsRenewalUrlExtension : public StringExtension { 
    public:
        NsRenewalUrlExtension(const String &v);
        NsRenewalUrlExtension(CA& ca, Type type);
        NsRenewalUrlExtension(const NsRenewalUrlExtension &extension);
        virtual ~NsRenewalUrlExtension();

        NsRenewalUrlExtension& operator=(const NsRenewalUrlExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsRenewalUrlExtension();

    };
    class NsCaPolicyUrlExtension : public StringExtension { 
    public:
        NsCaPolicyUrlExtension(const String &v);
        NsCaPolicyUrlExtension(CA& ca, Type type);
        NsCaPolicyUrlExtension(const NsCaPolicyUrlExtension &extension);
        virtual ~NsCaPolicyUrlExtension();

        NsCaPolicyUrlExtension& operator=(const NsCaPolicyUrlExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsCaPolicyUrlExtension();

    };
    class NsSslServerNameExtension : public StringExtension { 
    public:
        NsSslServerNameExtension(const String &v);
        NsSslServerNameExtension(CA& ca, Type type);
        NsSslServerNameExtension(const NsSslServerNameExtension &extension);
        virtual ~NsSslServerNameExtension();

        NsSslServerNameExtension& operator=(const NsSslServerNameExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsSslServerNameExtension();

    };
    class NsCommentExtension : public StringExtension { 
    public:
        NsCommentExtension(const String &v);
        NsCommentExtension(CA& ca, Type type);
        NsCommentExtension(const NsCommentExtension &extension);
        virtual ~NsCommentExtension();

        NsCommentExtension& operator=(const NsCommentExtension& extension);

        void           setValue(const String &v);
        void           getValue() const;

        virtual void commit2Config(CA& ca, Type type);
    private:
        NsCommentExtension();
    };

}
}

#endif // LIMAL_CA_MGM_STRING_EXTENSION_HPP
