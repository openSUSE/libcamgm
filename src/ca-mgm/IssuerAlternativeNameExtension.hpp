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
#ifndef    CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
#define    CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/ExtensionBase.hpp>
#include  <ca-mgm/LiteralValues.hpp>
#include <ca-mgm/PtrTypes.hpp>


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
		ca_mgm::RWCOW_pointer<IssuerAlternativeNameExtImpl> m_impl;
    	
	};

}

#endif // CA_MGM_ISSUER_ALTERNATIVE_NAME_EXTENSION_HPP
