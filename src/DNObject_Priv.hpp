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

  File:       DNObject_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class CA;
	
	class RDNObject_Priv : public RDNObject {
	public:
		RDNObject_Priv();
		RDNObject_Priv(const String& type, const String& value,
		               const String& prompt = String(),
		               blocxx::UInt32 min = 0,
		               blocxx::UInt32 max = 0);

		virtual ~RDNObject_Priv();

		/**
		 * Set the RDN value
		 *
		 * @param type of the RDN
		 * @param value of the RDN
		 * @param prompt the prompt which is configured in the configfile
		 * @param min minimal string length of value; 0 == min not set
		 * @param max maximal string length of value; 0 == max not set
		 */
		void   setRDN(const String& type, const String& value,
		              const String& prompt = String(),
		              blocxx::UInt32 min = 0,
		              blocxx::UInt32 max = 0);

	};

	class DNObject_Priv : public DNObject {
	public:
		DNObject_Priv(X509_NAME *x509_name);
		DNObject_Priv(const DNObject_Priv& obj);    
		DNObject_Priv(const DNObject& obj);    
		virtual ~DNObject_Priv();
		
		DNObject_Priv& operator=(const DNObject_Priv& obj);
		
		void
		setDefaults2Config(CA& ca);
	};

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_PRIV_HPP
