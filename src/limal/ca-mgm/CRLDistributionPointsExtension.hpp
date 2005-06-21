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

  File:       CRLDistributionPointsExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DISTRIBUTION_POINTS_EXTENSION_HPP
#define    LIMAL_CA_MGM_CRL_DISTRIBUTION_POINTS_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class CRLDistributionPointsExtension : public ExtensionBase {
    public:
        CRLDistributionPointsExtension();
        CRLDistributionPointsExtension(CA& ca, Type type);
        CRLDistributionPointsExtension(const CRLDistributionPointsExtension& extension);
        virtual ~CRLDistributionPointsExtension();

        CRLDistributionPointsExtension& operator=(const CRLDistributionPointsExtension& extension);

        void         setCRLDistributionPoints(blocxx::List<LiteralValue>);
        blocxx::List<LiteralValue> getCRLDistributionPoints() const;

        virtual void commit2Config(CA& ca, Type type);

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

    private:
        blocxx::List<LiteralValue> altNameList;
    };

}
}

#endif // LIMAL_CA_MGM_CRL_DISTRIBUTION_POINTS_EXTENSION_HPP
