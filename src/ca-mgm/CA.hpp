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

  File:       CA.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

/**
 * @file   CA.hpp
 * @brief  This is a short description of the library.
 */
#ifndef    CA_MGM_CA_HPP
#define    CA_MGM_CA_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/RequestGenerationData.hpp>
#include  <ca-mgm/RequestData.hpp>
#include  <ca-mgm/CRLGenerationData.hpp>
#include  <ca-mgm/CRLData.hpp>
#include  <ca-mgm/CertificateIssueData.hpp>
#include  <ca-mgm/CertificateData.hpp>
#include  <ca-mgm/CAConfig.hpp>
#include  <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE
{
	class CAImpl;

	/**
	 * @brief Managing a CA repository
	 *
	 * This class provides methods for managing a CA repository.
	 * If you want to know how to use these methods and functions
	 * have a look at the <a href="examples.html">example page</a>
	 *
	 */
	class CA
	{
	public:

		/**
		 * Construct a CA object.
		 *
		 * @param caName the name of this CA.
		 * @param caPasswd the password of this CA.
		 * @param repos directory path to the repository root
		 */
		CA(const std::string& caName, const std::string& caPasswd, const std::string& repos=REPOSITORY);

		/**
		 * Destructor of CA.
		 */
		~CA();


		/**
		 * Create a new Sub CA and with the whole needed infrastructure.
		 * On error this method throws exceptions.
		 *
		 * @param newCaName the name for the new CA
		 * @param keyPasswd the password for the private key
		 * @param caRequestData data for the request generation
		 * @param caIssueData the required data to sign the request
		 *
		 * @return The name of the certificate file
		 */
		std::string
		createSubCA(const std::string& newCaName,
		            const std::string& keyPasswd,
		            const RequestGenerationData& caRequestData,
		            const CertificateIssueData& caIssueData);

		/**
		 * Create a certificate request in the specified CA
		 * On error this method throws exceptions.
		 *
		 * @param keyPasswd the password for the private key
		 * @param requestData the data for the request
		 * @param requestType the type of the request
		 *
		 * @return the name of the new request
		 */
		std::string
		createRequest(const std::string& keyPasswd,
		              const RequestGenerationData& requestData,
		              Type requestType);


		/**
		 * Issue a certificate in the specified CA
		 * On error this method throws exceptions.
		 *
		 * @param requestName the name of the request which sould be signed
		 * @param issueData the issuing data
		 * @param certType the type of the certificate
		 *
		 * @return the name of the certificate
		 */
		std::string
		issueCertificate(const std::string& requestName,
		                 const CertificateIssueData& issueData,
		                 Type certType);

		/**
		 * Create a certificate in the specified CA
		 * On error this method throws exceptions.
		 *
		 * @param keyPasswd the password for the private key
		 * @param requestData the data for the request
		 * @param certificateData the data of the certificate
		 * @param type the type of the certificate
		 *
		 * @return the name of the certificate
		 */
		std::string
		createCertificate(const std::string& keyPasswd,
		                  const RequestGenerationData& requestData,
		                  const CertificateIssueData&  certificateData,
		                  Type type);


		/**
		 * Revoke a certificate.
		 * On error this method throws exceptions.
		 *
		 * @note This function does not create a new CRL.
		 *
		 * @param certificateName the name of the certificate to revoke
		 * @param crlReason a crlReason object which describes the reason
		 * why this certificate is revoked.
		 *
		 */
		void
		revokeCertificate(const std::string& certificateName,
		                  const CRLReason& crlReason = CRLReason());

		/**
		 * Create a new CRL with the specified data.
		 * On error this method throws exceptions.
		 *
		 * @param crlData the data for the new CRL
		 *
		 */
		void
		createCRL(const CRLGenerationData& crlData);

		/**
		 * Import a request in a CA repository.
		 * On error this method throws exceptions.
		 *
		 * @param request the request data
		 * @param formatType the input format type
		 *
		 * @return the name of the request
		 */
		std::string
		importRequestData(const ca_mgm::ByteBuffer& request,
		                  FormatType formatType = E_PEM);

		/**
		 * Import a request in a CA repository.
		 * On error this method throws exceptions.
		 *
		 * @param requestFile the request file
		 * @param formatType the input format type
		 *
		 * @return the name of the request
		 */
		std::string
		importRequest(const std::string& requestFile,
		              FormatType formatType = E_PEM);


		/**
		 * Get a CertificateIssueData object with current signing default
		 * settings for this CA and the specific type.
		 * On error this method throws exceptions.
		 *
		 * @param type the requested certificate type
		 *
		 * @return a CertificateIssueData object with the current defaults
		 */
		CertificateIssueData
		getIssueDefaults(Type type);

		/**
		 * Get a RequestGenerationData object with current request default
		 * settings for this CA and the specific type.
		 * On error this method throws exceptions.
		 *
		 * @param type the requested certificate type
		 *
		 * @return a RequestGenerationData object with the current defaults
		 */
		RequestGenerationData
		getRequestDefaults(Type type);

		/**
		 * Get a CRLGenerationData object with current default
		 * settings for this CA.
		 * On error this method throws exceptions.
		 *
		 * @return a CRLGenerationData object with the current defaults
		 */
		CRLGenerationData
		getCRLDefaults();

		/**
		 * Set the signing defaults for this CA and the specific certType
		 * On error this method throws exceptions.
		 *
		 * @param type the requested certificate type
		 * @param defaults the new certificate defaults
		 *
		 */
		void
		setIssueDefaults(Type type,
		                 const CertificateIssueData& defaults);

		/**
		 * Set the request defaults for this CA and the specific certType
		 * On error this method throws exceptions.
		 *
		 * @param type the requested certificate type
		 * @param defaults the new certificate defaults
		 *
		 */
		void
		setRequestDefaults(Type type,
		                   const RequestGenerationData& defaults);

		/**
		 * Set CRL defaults for this CA
		 * On error this method throws exceptions.
		 *
		 * @param defaults the new CRL defaults
		 *
		 */
		void
		setCRLDefaults(const CRLGenerationData& defaults);


		/**
		 * Get an Array of maps with all certificates of the defined CA.
		 * On error this method throws exceptions.
		 *
		 * @return a list of maps with all certificates in this CA.
		 * the map keys are:
		 * <ul>
		 *   <li>certificate (the name of the certificate)</li>
		 *   <li>commonName</li>
		 *   <li>emailAddress</li>
		 *   <li>countryName</li>
		 *   <li>stateOrProvinceName</li>
		 *   <li>localityName</li>
		 *   <li>organizationName</li>
		 *   <li>organizationalUnitName</li>
		 *   <li>status (The status of the certificate: "valid", "revoked", "expired")</li>
		 * </ul>
		 */
		std::vector<std::map<std::string, std::string> >
		getCertificateList();


		/**
		 * Get an Array of maps with all requests of the defined CA.
		 * On error this method throws exceptions.
		 *
		 * @return a list of maps with all requests in this CA.
		 * the map keys are:
		 * <ul>
		 *   <li>request (the name of the request)</li>
		 *   <li>commonName</li>
		 *   <li>emailAddress</li>
		 *   <li>countryName</li>
		 *   <li>stateOrProvinceName</li>
		 *   <li>localityName</li>
		 *   <li>organizationName</li>
		 *   <li>organizationalUnitName</li>
		 *   <li>date</li>
		 * </ul>
		 */
		std::vector<std::map<std::string, std::string> >
		getRequestList();



		/**
		 * Parse this CA and return the data.
		 * On error this method throws exceptions.
		 *
		 * @return the CA data
		 */
		CertificateData
		getCA();

		/**
		 * Parse a request and return the data.
		 * On error this method throws exceptions.
		 *
		 * @param requestName the name of the Request
		 *
		 * @return the request data
		 */
		RequestData
		getRequest(const std::string& requestName);

		/**
		 * Parse a certificate and return the data.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 *
		 * @return the certificate data
		 */
		CertificateData
		getCertificate(const std::string& certificateName);


		/**
		 * Parse the current CRL of this CA and return the data.
		 * On error this method throws exceptions.
		 *
		 * @return the CRL data
		 */
		CRLData
		getCRL();


		/**
		 * Return the CA certificate in PEM or DER format.
		 * On error this method throws exceptions.
		 *
		 * @param exportType the type in which the CA should be exported
		 *
		 * @return this CA certificate
		 */
		ca_mgm::ByteBuffer
		exportCACert(FormatType exportType);

		/**
		 * Return the CA private key in PEM format.
		 * If a new Password is given, the key will be encrypted
		 * using the newPassword.
		 * If newPassword is empty the returned key is decrypted.
		 * On error this method throws exceptions.
		 *
		 * @param newPassword the password to encrypt the private key.
		 * If newPassword is empty, the key will be returned decrypted.
		 *
		 * @return the private key of the CA in PEM format
		 */
		ca_mgm::ByteBuffer
		exportCAKeyAsPEM(const std::string& newPassword);

		/**
		 * Return the CA private key in DER format.
		 * The private Key is decrypted.
		 * On error this method throws exceptions.
		 *
		 * @return the private key of the CA in DER format
		 */
		ca_mgm::ByteBuffer
		exportCAKeyAsDER();

		/**
		 * Return the CA certificate in PKCS12 format.
		 * If withChain is true, all issuer certificates
		 * will be included.
		 * On error this method throws exceptions.
		 *
		 * @param p12Password the password for the private key
		 * @param withChain should the certificate chain be included
		 * set this to true, otherwise set this to false
		 *
		 * @return the data in PKCS12 format
		 */
		ca_mgm::ByteBuffer
		exportCAasPKCS12(const std::string& p12Password,
		                 bool withChain = false);


		/**
		 * Return the specified certificate in PEM or DER format
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 * @param exportType the format in which the certificate
		 * should be exported
		 *
		 * @return the certificate data
		 *
		 */
		ca_mgm::ByteBuffer
		exportCertificate(const std::string& certificateName,
		                  FormatType exportType);

		/**
		 * Return the certificate private key in PEM format.
		 * If a new Password is given, the key will be encrypted
		 * using the newPassword.
		 * If newPassword is empty the returned key is decrypted.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 * @param keyPassword the current password of the key.
		 * @param newPassword the password to encrypt the private key.
		 * If newPassword is empty, the key will be returned decrypted.
		 *
		 * @return the private key of the certificate in PEM format
		 */
		ca_mgm::ByteBuffer
		exportCertificateKeyAsPEM(const std::string& certificateName,
		                          const std::string& keyPassword,
		                          const std::string& newPassword);

		/**
		 * Return the certificate private key in DER format.
		 * The private Key is decrypted.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 * @param keyPassword the current password of the key.
		 *
		 * @return the private key in DER format
		 */
		ca_mgm::ByteBuffer
		exportCertificateKeyAsDER(const std::string& certificateName,
		                          const std::string& keyPassword);

		/**
		 * Return the certificate in PKCS12 format.
		 * If withChain is true, all issuer certificates
		 * will be included.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 * @param keyPassword the current password of the key.
		 * @param p12Password the password for the private key
		 * @param withChain should the certificate chain be included
		 * set this to true, otherwise set this to false
		 *
		 * @return the data in PKCS12 format
		 */
		ca_mgm::ByteBuffer
		exportCertificateAsPKCS12(const std::string& certificateName,
		                          const std::string& keyPassword,
		                          const std::string& p12Password,
		                          bool withChain = false);

		/**
		 * Export the CRL of this CA in the requested format type.
		 * On error this method throws exceptions.
		 *
		 * @param exportType the format type
		 *
		 * @return the CRL in the requested format
		 */
		ca_mgm::ByteBuffer
		exportCRL(FormatType exportType);


		/**
		 * Delete a Request. This function removes also
		 * the private key if one is available.
		 * On error this method throws exceptions.
		 *
		 * @param requestName the name of the request
		 *
		 */
		void
		deleteRequest(const std::string& requestName);

		/**
		 * Delete the specified certificate together with the corresponding
		 * request and private key if <b>requestToo</b> is set to true.
		 * This function works only for revoked or expired certificates.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the certificate to delete
		 * @param requestToo if set to true also request and key file
		 * will be deleted if they exists
		 *
		 */
		void
		deleteCertificate(const std::string& certificateName,
		                  bool requestToo = true);


		/**
		 * Update the internal openssl database.
		 * On error this method throws exceptions.
		 *
		 */
		void
		updateDB();

		/**
		 * Verify a certificate.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 * @param crlCheck verify against the CRLs
		 * @param purpose check for a specific certificate purpose
		 * valid purpose string are:
		 * <ul>
		 *   <li>sslclient</li>
		 *   <li>sslserver</li>
		 *   <li>nssslserver</li>
		 *   <li>smimesign</li>
		 *   <li>smimeencrypt</li>
		 *   <li>crlsign</li>
		 *   <li>ocsphelper</li>
		 *   <li>any (default)</li>
		 * </ul>
		 *
		 * @return true if the certificate is valid, otherwise false.
		 */
		bool
		verifyCertificate(const std::string& certificateName,
		                  bool crlCheck = true,
		                  const std::string& purpose = std::string("any"));

		/**
		 * Return the current config object
		 *
		 * @return the config object
		 */
		CAConfig*
		getConfig();


		/* ##########################################################################
		 * ###          static Functions                                          ###
		 * ##########################################################################
		 */

		/**
		 * Create a new selfsigned root CA plus the
		 * whole needed infrastructure.
		 * On error this function throws exceptions.
		 *
		 * @param caName the name for this CA
		 * @param caPasswd the password for this CA
		 * @param caRequestData the data for the request
		 * @param caIssueData the data to signing the CA
		 * @param repos the path to the repository root directory
		 *
		 */
		static void
		createRootCA(const std::string& caName,
		             const std::string& caPasswd,
		             const RequestGenerationData& caRequestData,
		             const CertificateIssueData& caIssueData,
		             const std::string& repos=REPOSITORY);


		/**
		 * Import a CA certificate and private key and creates a
		 * infrastructure.
		 * On error this function throws exceptions.
		 *
		 * @param caName the name of the CA
		 * @param caCertificate the CA certificate data in PEM format
		 * @param caKey the private key in PEM format
		 * @param caPasswd password of the private key or a new password if the key is unencrypted
		 * @param repos the path to the repository root directory
		 *
		 */
		static void
		importCA(const std::string& caName,
		         const ca_mgm::ByteBuffer& caCertificate,
		         const ca_mgm::ByteBuffer& caKey,
		         const std::string& caPasswd = std::string(),
		         const std::string& repos=REPOSITORY);

		/**
		 * Get a list of available CAs
		 * On error this function throws exceptions.
		 *
		 * @param repos the path to the repository root directory
		 *
		 * @return Array of std::strings of available CAs
		 */
		static std::vector<std::string>
		getCAList(const std::string& repos=REPOSITORY);

		/**
		 * Return a table of the available CAs and its issuer.
		 * If the CA is self-signed the issuer field is empty.
		 *
		 * <table>
		 *   <tr><th>caName</th><th>issuer caName</th></tr>
		 *   <tr><td>RootCA</td><td>&nbsp;</td></tr>
		 *   <tr><td>UserCA</td><td>RootCA</td></tr>
		 *   <tr><td>IPSecCA</td><td>UserCA</td></tr>
		 * </table>
		 *
		 * On error this function throws exceptions.
		 *
		 * @param repos the path to the repository root directory
		 *
		 * @return a list of lists of the available CAs
		 */
		static std::list<std::vector<std::string> >
		getCATree(const std::string& repos=REPOSITORY);

		/**
		 * Get a CertificateIssueData object with current signing default
		 * settings for a Root CA.
		 * On error this function throws exceptions.
		 *
		 * @param repos the path to the repository root directory
		 *
		 * @return a CertificateIssueData object with the current defaults
		 */
		static CertificateIssueData
		getRootCAIssueDefaults(const std::string& repos=REPOSITORY);

		/**
		 * Get a RequestGenerationData object with current request default
		 * settings for a Root CA.
		 * On error this function throws exceptions.
		 *
		 * @param repos the path to the repository root directory
		 *
		 * @return a RequestGenerationData object with the current defaults
		 */
		static RequestGenerationData
		getRootCARequestDefaults(const std::string& repos=REPOSITORY);


		/**
		 * Delete a Certificate Authority infrastructure
		 *
		 * Normaly you can only delete a CA if the CA certificate is expired or
		 * you have never signed a certificate with this CA. In all other cases
		 * you have to set the force parameter to "true" if you realy want to delete
		 * the CA and you know what you do.
		 * On error this function throws exceptions.
		 *
		 * @param caName the name of the CA to delete
		 * @param caPasswd the password of the CA
		 * @param force no checks, simply delete the CA
		 * @param repos the path to the repository root directory
		 *
		 */
		static void
		deleteCA(const std::string& caName,
		         const std::string& caPasswd,
		         bool  force = false,
		         const std::string& repos = REPOSITORY);

	private:
		ca_mgm::RWCOW_pointer<CAImpl> m_impl;


		CA();
		CA(const CA&);

		CA&
		operator=(const CA&);

		/**
		 * Check if the given dn matches the policy defined in the
		 * configuration file
		 * On error this method throws exceptions.
		 *
		 * @param dn the DN object
		 * @param type the Type of the certificate which should be signed
		 *
		 */
		void
		checkDNPolicy(const DNObject& dn, Type type);

		/**
		 * Initialize the config file
		 * On error this method throws exceptions.
		 *
		 * Copy the template to a configfile and create the config object
		 *
		 * @return the name of the config file
		 */
		std::string
		initConfigFile();

		/**
		 * Copy Config file to template
		 * On error this method throws exceptions.
		 */
		void
		commitConfig2Template();

		/**
		 * remove _default values from configfile
		 */
		void
		removeDefaultsFromConfig();
	};

}       // End of CA_MGM_NAMESPACE


/** @example CreateRootCA.cpp
 *
 * This is an example which shows how to create a root CA.
 */

/** @example CreateCertificate.cpp
 *
 * This is an example which shows how to create a Certificate.
 */

/** @example RevokeCertificateAndCreateCRL.cpp
 *
 * This example show how to revoke a certificate and create
 * a certificate revocation list (CRL)
 */

/** @example Export.cpp
 *
 * This example shows how to export CAs, keys, certificates and CRLs
 * from the repository
 */

#endif  // CA_MGM_HPP

