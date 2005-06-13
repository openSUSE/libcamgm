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

    class IssuerAlternativeNameExtension : public ExtensionBase {
    public:
        IssuerAlternativeNameExtension(bool copyIssuer = false, 
                                       const blocxx::List<LiteralValueBase> &alternativeNameList = blocxx::List<LiteralValueBase>());
        IssuerAlternativeNameExtension(CA& ca, Type type);
        IssuerAlternativeNameExtension(const IssuerAlternativeNameExtension& extension);
        virtual ~IssuerAlternativeNameExtension();

        IssuerAlternativeNameExtension& operator=(const IssuerAlternativeNameExtension& extension);

        void  setCopyIssuer(bool copyIssuer);
        bool  getCopyIssuer() const;

        void                   setAlternativeNameList(const blocxx::List<LiteralValueBase> &alternativeNameList);
        blocxx::List<LiteralValueBase> getAlternativeNameList() const;

        void                   addIssuerAltName(const LiteralValueBase& altName);

        virtual void           commit2Config(CA& ca, Type type);

    private:
        bool issuerCopy;
        blocxx::List<LiteralValueBase> altNameList;
    };

}
}

#endif // LIMAL_CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
