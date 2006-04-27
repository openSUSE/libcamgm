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

  File:       DNObject.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class CAConfig;
	class RDNObjectImpl;
	class DNObjectImpl;
	
	class RDNObject {
	public:
		RDNObject();
		RDNObject(const RDNObject& rdn);
		virtual ~RDNObject();

#ifndef SWIG
		
		RDNObject& operator=(const RDNObject& rdn);

#endif
		void   setRDNValue(const String& value);

		String getType() const;
		String getValue() const;

		String getOpenSSLValue() const;

		virtual bool                 valid() const;
		virtual blocxx::StringArray  verify() const;

		virtual blocxx::StringArray  dump() const;

#ifndef SWIG

		friend bool operator==(const RDNObject &l, const RDNObject &r);
		friend bool operator<(const RDNObject &l, const RDNObject &r);

#endif
		
	protected:
		blocxx::COWIntrusiveReference<RDNObjectImpl> m_impl;
    	
	};

	class DNObject {
	public:
		DNObject();
		DNObject(CAConfig* caConfig, Type type);
		DNObject(const blocxx::List<RDNObject> &dn);
		DNObject(const DNObject& dn);
		virtual ~DNObject();

#ifndef SWIG

		DNObject& operator=(const DNObject& dn);

#endif
		
		void                         setDN(const blocxx::List<RDNObject> &dn);
		blocxx::List<RDNObject>      getDN() const;

		String                       getOpenSSLString() const;

		virtual bool                 valid() const;
		virtual blocxx::StringArray  verify() const;
        
		virtual blocxx::StringArray  dump() const;

	protected:
		blocxx::COWIntrusiveReference<DNObjectImpl> m_impl;
    	
	private:
		blocxx::StringArray
		checkRDNList(const blocxx::List<RDNObject>& list) const;
	};

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_HPP
