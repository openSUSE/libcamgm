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

  File:       IssuerAlternativeNameExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
#define    LIMAL_CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    class IssuerAlternativeNameExtension : public ExtensionBase {
    public:
        IssuerAlternativeNameExtension();

        IssuerAlternativeNameExtension(bool copyIssuer,
                                       const blocxx::List<LiteralValue> &alternativeNameList);
        IssuerAlternativeNameExtension(CAConfig* caConfig, Type type);
        IssuerAlternativeNameExtension(const IssuerAlternativeNameExtension& extension);
        virtual ~IssuerAlternativeNameExtension();

        IssuerAlternativeNameExtension& operator=(const IssuerAlternativeNameExtension& extension);

        void  setCopyIssuer(bool copyIssuer);
        bool  getCopyIssuer() const;

        void  setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList);
        blocxx::List<LiteralValue> getAlternativeNameList() const;

        void                   addIssuerAltName(const LiteralValue& altName);

        virtual void           commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        bool issuerCopy;
        blocxx::List<LiteralValue> altNameList;
    };

}
}

#endif // LIMAL_CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
