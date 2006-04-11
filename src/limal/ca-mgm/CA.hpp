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
 * @file   Ca.hpp
 * @brief  This is a short description of the library.
 */
#ifndef    LIMAL_CA_HPP
#define    LIMAL_CA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/RequestGenerationData.hpp>
#include  <limal/ca-mgm/RequestData.hpp>
#include  <limal/ca-mgm/CRLGenerationData.hpp>
#include  <limal/ca-mgm/CRLData.hpp>
#include  <limal/ca-mgm/CertificateIssueData.hpp>
#include  <limal/ca-mgm/CertificateData.hpp>
#include  <limal/ca-mgm/CAConfig.hpp>
#include  <limal/ByteBuffer.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE
{
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
		CA(const String& caName, const String& caPasswd, const String& repos=REPOSITORY);
        
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
		String
		createSubCA(const String& newCaName,
		            const String& keyPasswd,
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
		String
		createRequest(const String& keyPasswd,
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
		String
		issueCertificate(const String& requestName,
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
		String
		createCertificate(const String& keyPasswd,
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
		revokeCertificate(const String& certificateName,
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
		String
		importRequestData(const limal::ByteBuffer& request,
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
		String
		importRequest(const String& requestFile,
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
		blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
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
		blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
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
		getRequest(const String& requestName);

		/**
		 * Parse a certificate and return the data.
		 * On error this method throws exceptions.
		 *
		 * @param certificateName the name of the certificate
		 *
		 * @return the certificate data
		 */
		CertificateData
		getCertificate(const String& certificateName);


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
		limal::ByteBuffer
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
		limal::ByteBuffer
		exportCAKeyAsPEM(const String& newPassword);

		/**
		 * Return the CA private key in DER format.
		 * The private Key is decrypted.
		 * On error this method throws exceptions.
		 *
		 * @return the private key of the CA in DER format
		 */
		limal::ByteBuffer
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
		limal::ByteBuffer
		exportCAasPKCS12(const String& p12Password,
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
		limal::ByteBuffer
		exportCertificate(const String& certificateName,
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
		limal::ByteBuffer
		exportCertificateKeyAsPEM(const String& certificateName,
		                          const String& keyPassword,
		                          const String& newPassword);

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
		limal::ByteBuffer
		exportCertificateKeyAsDER(const String& certificateName,
		                          const String& keyPassword);
        
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
		limal::ByteBuffer
		exportCertificateAsPKCS12(const String& certificateName,
		                          const String& keyPassword,
		                          const String& p12Password,
		                          bool withChain = false);
		
		/**
		 * Export the CRL of this CA in the requested format type.
		 * On error this method throws exceptions.
		 *
		 * @param exportFormat the format type
		 *
		 * @return the CRL in the requested format
		 */
		limal::ByteBuffer
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
		deleteRequest(const String& requestName);

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
		deleteCertificate(const String& certificateName, 
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
		verifyCertificate(const String& certificateName,
		                  bool crlCheck = true,
		                  const String& purpose = String("any"));

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
		createRootCA(const String& caName,
		             const String& caPasswd,
		             const RequestGenerationData& caRequestData,
		             const CertificateIssueData& caIssueData,
		             const String& repos=REPOSITORY);
        

		/**
		 * Import a CA certificate and private key and creates a 
		 * infrastructure.
		 * On error this function throws exceptions.
		 *
		 * @param caName the name of the CA
		 * @param caCertificate the CA certificate data in PEM format
		 * @param caKey the private key in PEM format
		 * @param caPasswd a password for the private key, if caKey is unencrypted
		 * @param repos the path to the repository root directory
		 *
		 */
		static void
		importCA(const String& caName,
		         const limal::ByteBuffer& caCertificate,
		         const limal::ByteBuffer& caKey,
		         const String& caPasswd = String(),
		         const String& repos=REPOSITORY);

		/**
		 * Get a list of available CAs
		 * On error this function throws exceptions.
		 *
		 * @param repos the path to the repository root directory
		 *
		 * @return Array of Strings of available CAs
		 */
		static blocxx::Array<blocxx::String>
		getCAList(const String& repos=REPOSITORY);
        
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
		static blocxx::List<blocxx::Array<blocxx::String> >
		getCATree(const String& repos=REPOSITORY);

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
		getRootCAIssueDefaults(const String& repos=REPOSITORY);

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
		getRootCARequestDefaults(const String& repos=REPOSITORY);


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
		deleteCA(const String& caName,
		         const String& caPasswd,
		         bool  force = false,
		         const String& repos = REPOSITORY);
		
	private:
		blocxx::COWIntrusiveReference<CAImpl> m_impl;


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
		String
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
}       // End of LIMAL_NAMESPACE


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

#endif  // LIMAL_CA_MGM_HPP

