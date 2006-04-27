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
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class CRLDistributionPointsExtImpl;
	
	class CRLDistributionPointsExt : public ExtensionBase
	{
	public:
		CRLDistributionPointsExt();
		CRLDistributionPointsExt(CAConfig* caConfig, Type type);
		CRLDistributionPointsExt(const CRLDistributionPointsExt& extension);
		virtual ~CRLDistributionPointsExt();

#ifndef SWIG

		CRLDistributionPointsExt&
		operator=(const CRLDistributionPointsExt& extension);

#endif
		
		void
		setCRLDistributionPoints(blocxx::List<LiteralValue>);
        
		blocxx::List<LiteralValue>
		getCRLDistributionPoints() const;

		virtual void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<CRLDistributionPointsExtImpl> m_impl;
		
	};

}
}

#endif // LIMAL_CA_MGM_CRL_DISTRIBUTION_POINTS_EXTENSION_HPP
