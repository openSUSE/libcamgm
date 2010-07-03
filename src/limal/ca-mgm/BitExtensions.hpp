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

  File:       BitExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_BIT_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_BIT_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class CAConfig;
	class BitExtensionImpl;
	
    /**
     * Base Class for Bit Extensions
     */
	class BitExtension : public ExtensionBase
	{
	public:
		BitExtension();
		BitExtension(uint32_t value);
		BitExtension(const BitExtension& extension);
		virtual ~BitExtension();

#ifndef SWIG

		BitExtension&  operator=(const BitExtension& extension);

#endif
		
		void           setValue(uint32_t value);
		uint32_t getValue() const;

		virtual void   commit2Config(CA& ca, Type type) const = 0;

		virtual bool                 valid() const  = 0;
		virtual std::vector<std::string>  verify() const = 0;

		virtual std::vector<std::string>  dump() const = 0;

	protected:
		blocxx::COWIntrusiveReference<BitExtensionImpl> m_impl;

	};

	/**
     * This extension describes the usage of this
     * certificate
     */
	class KeyUsageExt : public BitExtension {
	public:
		enum KeyUsage {
			digitalSignature  = 0x0080, // KU_DIGITAL_SIGNATURE
			nonRepudiation    = 0x0040, // KU_NON_REPUDIATION
			keyEncipherment   = 0x0020, // KU_KEY_ENCIPHERMENT
			dataEncipherment  = 0x0010, // KU_DATA_ENCIPHERMENT
			keyAgreement      = 0x0008, // KU_KEY_AGREEMENT
			keyCertSign       = 0x0004, // KU_KEY_CERT_SIGN
			cRLSign           = 0x0002, // KU_CRL_SIGN
			encipherOnly      = 0x0001, // KU_ENCIPHER_ONLY
			decipherOnly      = 0x8000  // KU_DECIPHER_ONLY
		};
        
		KeyUsageExt();
		KeyUsageExt(CAConfig* caConfig, Type type);

		/**
		 * Create an object with a specific key usage set
		 */
		KeyUsageExt(uint32_t keyUsage);
		KeyUsageExt(const KeyUsageExt& extension);
		virtual ~KeyUsageExt();

#ifndef SWIG

		KeyUsageExt& operator=(const KeyUsageExt& extension);

#endif
		
		/**
		 * Set a new key usage
		 */
		void           setKeyUsage(uint32_t keyUsage);

		/**
		 * Return the key usage
		 */
		uint32_t getKeyUsage() const;

		/**
		 * Return true if the specified bit is set
		 */
		bool isEnabledFor(KeyUsage ku) const;

		/**
		 * Write the informations of this object back to the configuration file
		 *
		 * @param ca the CA object which holds the config object
		 * @param type the type describes the section of the config file
		 */
		virtual void commit2Config(CA& ca, Type type) const ;

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
		bool  validKeyUsage(uint32_t keyUsage) const;
	};

	/**
     * This extension describes the usage of this
     * certificate (Netscape specific)
     */
	class NsCertTypeExt : public BitExtension {
	public:
		enum NsCertType {
			client   = 0x0080, // NS_SSL_CLIENT
			server   = 0x0040, // NS_SSL_SERVER
			email    = 0x0020, // NS_SMIME
			objsign  = 0x0010, // NS_OBJSIGN
			reserved = 0x0008, // ??
			sslCA    = 0x0004, // NS_SSL_CA
			emailCA  = 0x0002, // NS_SMIME_CA
			objCA    = 0x0001  // NS_OBJSIGN_CA
		};
        
		NsCertTypeExt();
		NsCertTypeExt(CAConfig* caConfig, Type type);

		/**
		 * Create an object with a specific certificate type set
		 */
		NsCertTypeExt(uint32_t nsCertTypes);
		NsCertTypeExt(const NsCertTypeExt& extension);
		virtual ~NsCertTypeExt();

#ifndef SWIG

		NsCertTypeExt& operator=(const NsCertTypeExt& extension);

#endif
		
		/**
		 * Set a new certificate type
		 */
		void           setNsCertType(uint32_t nsCertTypes);

		/**
		 * Return the certificate type
		 */
		uint32_t getNsCertType() const;
        
		/**
		 * Return true if the specified bit is set
		 */
		bool           isEnabledFor(NsCertType nsCertType) const;

		/**
		 * Write the informations of this object back to the configuration file
		 *
		 * @param ca the CA object which holds the config object
		 * @param type the type describes the section of the config file
		 */
		virtual void   commit2Config(CA& ca, Type type) const;

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
	};

}

#endif // LIMAL_CA_MGM_BIT_EXTENSIONS_HPP
