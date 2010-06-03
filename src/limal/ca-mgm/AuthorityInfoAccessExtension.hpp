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

  File:       AuthorityInfoAccessExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class AuthorityInformationImpl;
	class AuthorityInfoAccessExtImpl;
	
	class AuthorityInformation {

	public:
		/**
		 * Construct an empty AuthorityInformation object
		 */
		AuthorityInformation();

		/**
         * Construct an object with access OID and location
         *
         * @code
         *
         *   LiteralValue lv("URI", "http://www.example.com/ca/");
         *   AuthorityInformation ai("caIssuers", lv);
         *
         * @endcode
         *
         * @param accessOID <b>OCSP</b>, <b>caIssuers</b> or any valid OID
         * @param location location of the information
         *
         */
		AuthorityInformation(const String &accessOID, 
		                     const LiteralValue& location);

		/**
         * Copy an AuthorityInformation object
         */
		AuthorityInformation(const AuthorityInformation& ai);

		/**
		 * Destructor
		 */
		~AuthorityInformation();
				
#ifndef SWIG

		AuthorityInformation&
		operator=(const AuthorityInformation& ai);

#endif
		
		/**
         * Set new Authority Informations
         *
         * @param accessOID <b>OCSP</b>, <b>caIssuers</b> or any valid OID
         * @param location location of the information
         *
         */
		void
		setAuthorityInformation(const String &accessOID, 
		                        const LiteralValue& location);

		/**
         * Return the access OID
         */
		String
		getAccessOID() const;

        /**
         * Return the location object
         */
		LiteralValue
		getLocation() const;

        /**
         * Check if this object is valid
         *
         * @return true if this object is valid, otherwise false
         */
		bool
		valid() const;

        /**
         * Verify this object and return an Array with all
         * error messages.
         *
         * @return Array with error messages. If this Array is empty this
         * object is valid
         */
		blocxx::Array<String>
		verify() const;

        /**
         * Return the content of this object for debugging
         */
		blocxx::Array<String>
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const AuthorityInformation &l, const AuthorityInformation &r);
        
		friend bool
		operator<(const AuthorityInformation &l, const AuthorityInformation &r);

#endif
		
	private:
		blocxx::COWIntrusiveReference<AuthorityInformationImpl> m_impl;

	};

    /**
     * The authority information access extension gives details
     * about how to access certain information relating to the CA.
     *
     * @code
     *
     *   LiteralValue lv("URI", "http://www.example.com/ca/");
     *   AuthorityInformation ai("caIssuers", lv);
     *
     *   List<AuthorityInformation> list;
     *   list.push_back(ai);
     *
     *   AuthorityInfoAccessExt aie;
     *   aie.setAuthorityInformation(list);
     *
     * @endcode
     */
    class AuthorityInfoAccessExt : public ExtensionBase {
    public:

        /**
         * Construct an empty object
         */
        AuthorityInfoAccessExt();

        AuthorityInfoAccessExt(const AuthorityInfoAccessExt& extension);

        /**
         * Construct an AuthorityInfoAccessExt object from a config object
         *
         * @param caConfig object of the configuration file
         * @param type the type describes the section of the config file
         *
         */
        AuthorityInfoAccessExt(CAConfig* caConfig, Type type);

        virtual ~AuthorityInfoAccessExt();

#ifndef SWIG

    	AuthorityInfoAccessExt&
        operator=(const AuthorityInfoAccessExt& extension);

#endif
    	
        /**
         * Set a new list of Authority Informations
         */
        void
        setAuthorityInformation(const blocxx::List<AuthorityInformation>& infolist);

        /**
         * Return the list with Authority Informations
         */
        blocxx::List<AuthorityInformation>
        getAuthorityInformation() const;

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
    	blocxx::COWIntrusiveReference<AuthorityInfoAccessExtImpl> m_impl;
    	
    };

}

#endif // LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
