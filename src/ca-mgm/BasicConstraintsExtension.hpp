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

  File:       BasicConstraintsExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
#define    CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/ExtensionBase.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class BasicConstraintsExtImpl;
	
    /**
     * If the ca parameter is set to true this certificate
     * is a Certificate Authority.
     * The pathlen parameter indicates the maximum number of CAs that can appear
     * below this one in a chain.
     */
	class BasicConstraintsExt : public ExtensionBase
	{
	public:
		BasicConstraintsExt();
		BasicConstraintsExt(CAConfig* caConfig, Type type);
		BasicConstraintsExt(bool isCa, int32_t pathLength=-1);
		BasicConstraintsExt(const BasicConstraintsExt& extension);
		virtual ~BasicConstraintsExt();

#ifndef SWIG

		BasicConstraintsExt& operator=(const BasicConstraintsExt& extension);

#endif
		
		/**
		 * Set the ca parameter and the path length.
		 *
		 * @param isCa set it to true if you want a CA, otherwise false.
		 * @param pathLength maximum number of CAs that can appear below this one in a chain;
		 * -1 means no path Length is set.
		 */
		void           setBasicConstraints(bool isCa, int32_t pathLength=-1);

		/**
		 * Return the ca parameter
		 */
		bool           isCA() const;

		/**
		 * Return the path length (-1 means no path length set)
		 */
		int32_t  getPathLength() const;

		/**
		 * Write the informations of this object back to the configuration file
		 *
		 * @param ca the CA object which holds the config object
		 * @param type the type describes the section of the config file
		 */
		virtual void commit2Config(CA& ca, Type type) const;

		/**
		 * Check if this object is valid
		 *
		 * @return true if this object is valid, otherwise false
		 */
		virtual bool                 valid() const;  

		/**
		 * Verify this object and return an Array with all
		 * error messages.
		 *
		 * @return Array with error messages. If this Array is empty this
		 * object is valid
		 */
		virtual std::vector<std::string>  verify() const; 

		/**
		 * Return the content of this object for debugging
		 */
		virtual std::vector<std::string>  dump() const;

	private:
		ca_mgm::RWCOW_pointer<BasicConstraintsExtImpl> m_impl;

	};

}

#endif // CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
