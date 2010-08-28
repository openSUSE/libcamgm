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

  File:       SubjectAlternativeNameExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
#define    LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/ExtensionBase.hpp>
#include  <ca-mgm/LiteralValues.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class SubjectAlternativeNameExtImpl;
	
	class SubjectAlternativeNameExt : public ExtensionBase {
	public:
		SubjectAlternativeNameExt();
        
		SubjectAlternativeNameExt(CAConfig* caConfig, Type type);
        
		SubjectAlternativeNameExt(bool copyEmail,
		                          const std::list<LiteralValue> &alternativeNameList = std::list<LiteralValue>());
        
		SubjectAlternativeNameExt(const SubjectAlternativeNameExt& extension);
		
		virtual ~SubjectAlternativeNameExt();
		
#ifndef SWIG

		SubjectAlternativeNameExt&
		operator=(const SubjectAlternativeNameExt& extension);

#endif
		
		void
		setCopyEmail(bool copyEmail);		                          
		
		void
		setAlternativeNameList(const std::list<LiteralValue> &alternativeNameList = std::list<LiteralValue>());
		
		bool
		getCopyEmail() const;
		
		std::list<LiteralValue>
		getAlternativeNameList() const;
		
		virtual void
		commit2Config(CA& ca, Type type) const;
		
		virtual bool
		valid() const;
		
		virtual std::vector<std::string>
		verify() const;
		
		virtual std::vector<std::string>
		dump() const;
		
	private:
		ca_mgm::RWCOW_pointer<SubjectAlternativeNameExtImpl> m_impl;
	};

}

#endif // LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
