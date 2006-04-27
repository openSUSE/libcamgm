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

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class SubjectAlternativeNameExtImpl;
	
	class SubjectAlternativeNameExt : public ExtensionBase {
	public:
		SubjectAlternativeNameExt();
        
		SubjectAlternativeNameExt(CAConfig* caConfig, Type type);
        
		SubjectAlternativeNameExt(bool copyEmail,
		                          const blocxx::List<LiteralValue> &alternativeNameList = blocxx::List<LiteralValue>());
        
		SubjectAlternativeNameExt(const SubjectAlternativeNameExt& extension);
		
		virtual ~SubjectAlternativeNameExt();
		
#ifndef SWIG

		SubjectAlternativeNameExt&
		operator=(const SubjectAlternativeNameExt& extension);

#endif
		
		void
		setCopyEmail(bool copyEmail);		                          
		
		void
		setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList = blocxx::List<LiteralValue>());
		
		bool
		getCopyEmail() const;
		
		blocxx::List<LiteralValue>
		getAlternativeNameList() const;
		
		virtual void
		commit2Config(CA& ca, Type type) const;
		
		virtual bool
		valid() const;
		
		virtual blocxx::StringArray
		verify() const;
		
		virtual blocxx::StringArray
		dump() const;
		
	private:
		blocxx::COWIntrusiveReference<SubjectAlternativeNameExtImpl> m_impl;
	};

}
}

#endif // LIMAL_CA_MGM_SUBJECT_ALTERNATIVE_NAME_EXTENSION_HPP
