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
#include  <blocxx/COWIntrusiveReference.hpp>


namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class IssuerAlternativeNameExtImpl;
	
	class IssuerAlternativeNameExt : public ExtensionBase {
	public:
		IssuerAlternativeNameExt();

		IssuerAlternativeNameExt(bool copyIssuer,
		                         const std::list<LiteralValue> &alternativeNameList);
        
		IssuerAlternativeNameExt(CAConfig* caConfig, Type type);
        
		IssuerAlternativeNameExt(const IssuerAlternativeNameExt& extension);
        
		virtual ~IssuerAlternativeNameExt();

#ifndef SWIG

		IssuerAlternativeNameExt&
		operator=(const IssuerAlternativeNameExt& extension);

#endif
		
		void
		setCopyIssuer(bool copyIssuer);
        
		bool
		getCopyIssuer() const;

		void
		setAlternativeNameList(const std::list<LiteralValue> &alternativeNameList);
        
		std::list<LiteralValue>
		getAlternativeNameList() const;

		void
		addIssuerAltName(const LiteralValue& altName);

		virtual void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	private:
		blocxx::COWIntrusiveReference<IssuerAlternativeNameExtImpl> m_impl;
    	
	};

}

#endif // LIMAL_CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
