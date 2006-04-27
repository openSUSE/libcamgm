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

  File:       AuthorityKeyIdentifierExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class AuthorityKeyIdentifierExtImpl;
	
	class AuthorityKeyIdentifierExt : public ExtensionBase {
	public:

		AuthorityKeyIdentifierExt();
		AuthorityKeyIdentifierExt(const AuthorityKeyIdentifierExt& extension);
		virtual ~AuthorityKeyIdentifierExt();

#ifndef SWIG

		AuthorityKeyIdentifierExt&
		operator=(const AuthorityKeyIdentifierExt& extension);

#endif
		
		/**
         * Return the key ID  of the Authority
         */
		String
		getKeyID() const;

        /**
         * Return the DirName of the Authority
         */
		String
		getDirName() const;

        /**
         * Return the serial number of the Authority
         */
		String
		getSerial() const;

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

	protected:
		blocxx::COWIntrusiveReference<AuthorityKeyIdentifierExtImpl> m_impl;
		
		void
		setKeyID(const String& kid);
		
		void
		setDirName(const String& dirName);
		
		void
		setSerial(const String& serial);

	private:
		virtual void commit2Config(CA& ca, Type type) const;
	};

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP
