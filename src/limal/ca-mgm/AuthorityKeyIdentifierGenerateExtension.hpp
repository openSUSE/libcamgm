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

  File:       AuthorityKeyIdentifierGenerateExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class AuthorityKeyIdentifierGenerateExtImpl;
	
    /**
     * If the keyid option is present an attempt is made to copy the subject key
     * identifier from the parent certificate.
     * The issuer option copies the issuer and serial number from the issuer
     * certificate.
     */
	class AuthorityKeyIdentifierGenerateExt : public ExtensionBase {
	public:

		enum KeyID {
			KeyID_none,   /*!< no key ID */ 
			KeyID_normal, /*!< include key ID if possible*/
			KeyID_always  /*!< include key ID or return error */
		};
        
		enum Issuer {
			Issuer_none,   /*!< no issuer/serial */
			Issuer_normal, /*!< include issuer/serial if possible */
			Issuer_always  /*!< include issuer/serial or return error */
		};

		AuthorityKeyIdentifierGenerateExt();
		AuthorityKeyIdentifierGenerateExt(CAConfig* caConfig, Type type);

		/**
		 * Create an object with KeyID and Issuer option
		 */
		AuthorityKeyIdentifierGenerateExt(KeyID kid, Issuer iss);
		AuthorityKeyIdentifierGenerateExt(const AuthorityKeyIdentifierGenerateExt& extension);
		virtual ~AuthorityKeyIdentifierGenerateExt();

#ifndef SWIG

		AuthorityKeyIdentifierGenerateExt& 
		operator=(const AuthorityKeyIdentifierGenerateExt& extension);

#endif
		
		/**
		 * Set the Key ID
		 */
		void
		setKeyID(KeyID kid);

		/**
		 * Return the Key ID
		 */
		KeyID
		getKeyID() const;

		/**
		 * Set the issuer option
		 */
		void
		setIssuer(Issuer iss);

		/**
		 * Return the issuer option
		 */
		Issuer
		getIssuer() const;

		/**
		 * Write the informations of this object back to the configuration file
		 *
		 * @param ca the CA object which holds the config object
		 * @param type the type describes the section of the config file
		 */
		virtual void
		commit2Config(CA& ca, Type type) const;

		/**
		 * Check if this object is valid
		 *
		 * @return true if this object is valid, otherwise false
		 */
		virtual bool
		valid() const;  

		/**
		 * Verify this object and return an Array with all
		 * error messages.
		 *
		 * @return Array with error messages. If this Array is empty this
		 * object is valid
		 */
		virtual blocxx::StringArray
		verify() const; 

		/**
		 * Return the content of this object for debugging
		 */
		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<AuthorityKeyIdentifierGenerateExtImpl> m_impl;

	};

}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP
