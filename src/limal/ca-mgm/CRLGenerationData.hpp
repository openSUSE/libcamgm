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

  File:       CRLGenerationData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP
#define    LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CRLGenerationExtensions.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace CA_MGM_NAMESPACE
{

	class CA;
	class CRLGenerationDataImpl;
	/**
	 * @brief Data representation to generate a CRL
	 *
	 * This class is a data representation to generate a CRL.
	 */
	class CRLGenerationData {
	public:
		CRLGenerationData();
		CRLGenerationData(CAConfig* caConfig, Type type);
		CRLGenerationData(blocxx::UInt32 hours, 
		                  const X509v3CRLGenerationExts& ext);
		CRLGenerationData(const CRLGenerationData& data);
		virtual ~CRLGenerationData();
        
#ifndef SWIG

		CRLGenerationData&
		operator=(const CRLGenerationData& data);

#endif
		
		void
		setCRLLifeTime(blocxx::UInt32 hours);
        
		blocxx::UInt32
		getCRLLifeTime() const;

		void
		setExtensions(const X509v3CRLGenerationExts& ext);
        
		X509v3CRLGenerationExts
		getExtensions() const;

		X509v3CRLGenerationExts&
		extensions();

		void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual std::vector<blocxx::String>
		verify() const;

		virtual std::vector<blocxx::String>
		dump() const;

	private:
		blocxx::COWIntrusiveReference<CRLGenerationDataImpl> m_impl;

	};

}

#endif // LIMAL_CA_MGM_CRL_GENERATION_DATA_HPP
