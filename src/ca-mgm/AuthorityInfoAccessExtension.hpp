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
#ifndef    CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
#define    CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/LiteralValues.hpp>
#include  <ca-mgm/ExtensionBase.hpp>
#include <ca-mgm/PtrTypes.hpp>

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
		AuthorityInformation(const std::string &accessOID,
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
		setAuthorityInformation(const std::string &accessOID,
		                        const LiteralValue& location);

		/**
         * Return the access OID
         */
		std::string
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
		std::vector<std::string>
		verify() const;

        /**
         * Return the content of this object for debugging
         */
		std::vector<std::string>
		dump() const;

#ifndef SWIG

		friend bool
		operator==(const AuthorityInformation &l, const AuthorityInformation &r);

		friend bool
		operator<(const AuthorityInformation &l, const AuthorityInformation &r);

#endif

	private:
		ca_mgm::RWCOW_pointer<AuthorityInformationImpl> m_impl;

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
        setAuthorityInformation(const std::list<AuthorityInformation>& infolist);

        /**
         * Return the list with Authority Informations
         */
        std::list<AuthorityInformation>
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
        virtual std::vector<std::string>
        verify() const;

        /**
         * Return the content of this object for debugging
         */
        virtual std::vector<std::string>
        dump() const;

    private:
    	ca_mgm::RWCOW_pointer<AuthorityInfoAccessExtImpl> m_impl;

    };

}

#endif // CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
