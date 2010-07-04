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
#include <limal/PtrTypes.hpp>

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
		setCRLDistributionPoints(std::list<LiteralValue>);
        
		std::list<LiteralValue>
		getCRLDistributionPoints() const;

		virtual void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	private:
		ca_mgm::RWCOW_pointer<CRLDistributionPointsExtImpl> m_impl;
		
	};

}

#endif // LIMAL_CA_MGM_CRL_DISTRIBUTION_POINTS_EXTENSION_HPP
