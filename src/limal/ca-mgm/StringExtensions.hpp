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

  File:       StringExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_STRING_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_STRING_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {
    
namespace CA_MGM_NAMESPACE {

    class CA;
    
    class StringExtension : public ExtensionBase {
        
    public:
        StringExtension();
        virtual ~StringExtension();

        virtual void   setValue(const String &v) = 0;
        virtual String getValue() const = 0;
        
        virtual void commit2Config(CA& ca, Type type) const = 0;
        
        virtual bool                 valid() const = 0;
        virtual blocxx::StringArray  verify() const = 0;

        virtual blocxx::StringArray  dump() const = 0;

    protected:
        StringExtension(const String &v );
        StringExtension(const StringExtension& extension);
        
        StringExtension& operator=(const StringExtension& extension);
        
        String value;
       
    };

    class NsBaseUrlExtension : public StringExtension { 
    public:
        NsBaseUrlExtension();
        NsBaseUrlExtension(const String &v);
        NsBaseUrlExtension(CA& ca, Type type);
        NsBaseUrlExtension(const NsBaseUrlExtension &extension);
        virtual ~NsBaseUrlExtension();

        NsBaseUrlExtension& operator=(const NsBaseUrlExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const ;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };

    class NsRevocationUrlExtension : public StringExtension { 
    public:
        NsRevocationUrlExtension();
        NsRevocationUrlExtension(const String &v);
        NsRevocationUrlExtension(CA& ca, Type type);
        NsRevocationUrlExtension(const NsRevocationUrlExtension &extension);
        virtual ~NsRevocationUrlExtension();

        NsRevocationUrlExtension& operator=(const NsRevocationUrlExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };

    class NsCaRevocationUrlExtension : public StringExtension { 
    public:
        NsCaRevocationUrlExtension();
        NsCaRevocationUrlExtension(const String &v);
        NsCaRevocationUrlExtension(CA& ca, Type type);
        NsCaRevocationUrlExtension(const NsCaRevocationUrlExtension &extension);
        virtual ~NsCaRevocationUrlExtension();

        NsCaRevocationUrlExtension& operator=(const NsCaRevocationUrlExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const; 

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };

    class NsRenewalUrlExtension : public StringExtension { 
    public:
        NsRenewalUrlExtension();
        NsRenewalUrlExtension(const String &v);
        NsRenewalUrlExtension(CA& ca, Type type);
        NsRenewalUrlExtension(const NsRenewalUrlExtension &extension);
        virtual ~NsRenewalUrlExtension();

        NsRenewalUrlExtension& operator=(const NsRenewalUrlExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };
    class NsCaPolicyUrlExtension : public StringExtension { 
    public:
        NsCaPolicyUrlExtension();
        NsCaPolicyUrlExtension(const String &v);
        NsCaPolicyUrlExtension(CA& ca, Type type);
        NsCaPolicyUrlExtension(const NsCaPolicyUrlExtension &extension);
        virtual ~NsCaPolicyUrlExtension();

        NsCaPolicyUrlExtension& operator=(const NsCaPolicyUrlExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const; 

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };
    class NsSslServerNameExtension : public StringExtension { 
    public:
        NsSslServerNameExtension();
        NsSslServerNameExtension(const String &v);
        NsSslServerNameExtension(CA& ca, Type type);
        NsSslServerNameExtension(const NsSslServerNameExtension &extension);
        virtual ~NsSslServerNameExtension();

        NsSslServerNameExtension& operator=(const NsSslServerNameExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };
    class NsCommentExtension : public StringExtension { 
    public:
        NsCommentExtension();
        NsCommentExtension(const String &v);
        NsCommentExtension(CA& ca, Type type);
        NsCommentExtension(const NsCommentExtension &extension);
        virtual ~NsCommentExtension();

        NsCommentExtension& operator=(const NsCommentExtension& extension);

        void           setValue(const String &v);
        String         getValue() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };

}
}

#endif // LIMAL_CA_MGM_STRING_EXTENSION_HPP
