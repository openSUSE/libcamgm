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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{
    /**
     * @brief Managing a CA repository
     *
     * This class provides methods for managing a CA repository
     */
    class CA
    {
    public:
        /**
         * Construct a CA object. 
         *
         * @param caName the name of this CA.
         * @param caPasswd the password of this CA.
         * @param repos directory path to the repository
         */
        CA(const String& caName, const String& caPasswd, const String& repos=REPOSITORY);
        
        /**
         * Destructor of CA.
         */
        ~CA();
        

        /**
         * Create a new Sub CA and creates the whole needed infrastructure.
         *
         * @param CertificateData the required certificate data
         *
         * @return true for success otherwise false
         */
        bool createSubCA(const String& newCaName,
                         const String& keyPasswd,
                         const RequestGenerationData& caRequestData,
                         const CertificateIssueData& caIssueData);

        /**
         * Create a certificate request in the specified CA
         *
         * @param requestData the data for the request
         *
         * @return the name of the request
         */
        String createRequest(const String& keyPasswd,
                             const RequestGenerationData& requestData,
                             Type requestType);


        /**
         * Issue a certificate in the specified CA
         *
         * @param requestName the name of the request which sould be signed
         * @param issueData the issuing data
         *
         * @return the name of the certificate
         */
        String issueCertificate(const String& requestName,
                                const CertificateIssueData& issueData,
                                Type certType);

        /**
         * Create a certificate in the specified CA
         *
         * @param certificateData the data of the certificate
         *
         * @return the name of the certificate
         */    
        String createCertificate(const String& keyPasswd,
                                 const RequestGenerationData& requestData,
                                 const CertificateIssueData&  certificateData,
                                 Type type);


        /**
         * Revoke a certificate. 
         *
         * @note This function does not create a new CRL.
         *
         * @param certificateName the name of the certificate to revoke
         * @param crlReason a crlReason object which describes the reason
         * why this certificate is revoked.
         *
         * @return true on success, otherwise false.
         */
        bool revokeCertificate(const String& certificateName,
                               const CRLReason& crlReason = CRLReason());

        /**
         * Create a new CRL with the specified data.
         *
         * @param crlData the data for the new CRL
         *
         * @return true on success, otherwise false
         */
        bool createCRL(const CRLGenerationData& crlData);

        /**
         * Import a request in a CA repository.
         *
         * @param request the request data
         * @param formatType the input format type
         *
         * @return the name of the request
         */
        String importRequest(const ByteArray& request,
                             FormatType formatType = PEM);

        /**
         * Import a request in a CA repository.
         *
         * @param requestFile the request file
         * @param formatType the input format type
         *
         * @return the name of the request
         */
        String importRequest(const String& requestFile,
                             FormatType formatType = PEM);


        /**
         * Get a CertificateIssueData object with current signing default
         * settings for the specific CA and type.
         *
         * @param type the requested certificate type 
         *
         * @return a CertificateIssueData object with the current defaults
         */
        CertificateIssueData  getIssueDefaults(Type type);

        /**
         * Get a RequestGenerationData object with current request default
         * settings for the specific CA and certType.
         *
         * @param type the requested certificate type 
         *
         * @return a RequestGenerationData object with the current defaults
         */
        RequestGenerationData getRequestDefaults(Type type);

        /**
         * Get a CRLGenerationData object with current default
         * settings for the specific CA.
         *
         * @return a CRLGenerationData object with the current defaults
         */
        CRLGenerationData     getCRLDefaults();

        /**
         * Set the signing defaults for the specific CA and certType
         *
         * @param type the requested certificate type 
         * @param defaults the new certificate defaults
         *
         * @return true on success, otherwise false
         */
        bool  setIssueDefaults(Type type,
                               const CertificateIssueData& defaults);

        /**
         * Set the request defaults for the specific CA and certType
         *
         * @param type the requested certificate type 
         * @param defaults the new certificate defaults
         *
         * @return true on success, otherwise false
         */
        bool  setRequestDefaults(Type type,
                                 const RequestGenerationData& defaults);

        /**
         * Set CRL defaults for the specific CA
         *
         * @param defaults the new certificate defaults
         *
         * @return true on success, otherwise false
         */
        bool  setCRLDefaults(const CRLGenerationData& defaults);
           

        /**
         * Get a list of maps with all certificates of the defined CA.
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
        blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > getCertificateList();


        /**
         * Get a list of maps with all requests of the defined CA.
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
        blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> > getRequestList();



        /**
         * Get the CertificateData of the specified CA
         *
         * @return the certificate data
         */
        CertificateData getCA();

        /**
         * Get the specified request
         *
         * @param requestName the name of the Request
         */
        RequestData getRequest(const String& requestName);

        /**
         * Get the specified certificate
         *
         * @param certificateName the name of the Certificate
         *
         * @return the certificate data
         */
        CertificateData getCertificate(const String& certificateName);


        /**
         * Get the data of the current CRL in the specified CA
         *
         * @return the CRL data
         */
        CRLData getCRL();

       
        /** 
         * Return the CA certificate in PEM or DER format
         *
         */
        ByteArray exportCACert(FormatType exportType);
        
        /**
         * Return the CA private key in PEM format.
         * If a new Password is given, the key will be encrypted
         * using the newPassword. 
         * If newPassword is empty the returned key is decrypted.
         */
        ByteArray exportCAKeyAsPEM(const String& newPassword);

        /**
         * Return the CA private key in DER format.
         * The private Key is decrypted.
         */
        ByteArray exportCAKeyAsDER();
        
        /**
         * Return the CA certificate in PKCS12 format.
         * If withChain is true, all issuer certificates
         * will be included.
         */
        ByteArray exportCAasPKCS12(const String& p12Password,
                                   bool withChain = false);
        
        
        /** 
         * Return the certificate in PEM or DER format
         *
         */
        ByteArray exportCertificate(const String& certificateName,
                                    FormatType exportType);
        
        /**
         * Return the certificate private key in PEM format.
         * If a new Password is given, the key will be encrypted
         * using the newPassword. 
         * If newPassword is empty the returned key is decrypted.
         */
        ByteArray exportCertificateKeyAsPEM(const String& certificateName,
                                            const String& keyPassword,
                                            const String& newPassword);

        /**
         * Return the certificate private key in DER format.
         * The private Key is decrypted.
         */
        ByteArray exportCertificateKeyAsDER(const String& certificateName,
                                            const String& keyPassword);
        
        /**
         * Return the certificate in PKCS12 format.
         * If withChain is true, all issuer certificates
         * will be included.
         */
        ByteArray exportCertificateAsPKCS12(const String& certificateName,
                                            const String& keyPassword,
                                            const String& p12Password,
                                            bool withChain = false);

        /**
         * Export a CRL in the requested format type.
         *
         * @param the format type
         *
         * @return the CRL in the requested format
         */
        ByteArray exportCRL(FormatType exportType);


        /**
         * Delete a Request. This function removes also
         * the private key if one is available.
         *
         * @param requestName the name of the request
         *
         * @return true on success, otherwise false
         */
        bool deleteRequest(const String& requestName);

        /**
         * Delete the specified certificate together with the corresponding 
         * request and private key if requestToo is set to true. 
         * This function works only for revoked or expired certificates.
         *
         * @param certificateName the certificate to delete
         * @param requestToo if set to true also request and key file 
         * will be deleted
         *
         * @return true on success, otherwise false.
         */
        bool deleteCertificate(const String& certificateName, 
                               bool requestToo = true);



        /**
         * Update the internal openssl database. 
         *
         * @param caPasswd the password of the CA
         *
         * @return true on success, otherwise false
         */
        bool updateDB();
        
        /**
         * Verify a certificate.
         *
         * @param certificateName the name of the certificate 
         * @param crlCheck verify against the CRLs
         * @param purpose check for a specific certificate purpose
         *
         * @return true if the certificate is valid, otherwise false.
         */
        bool verifyCertificate(const String& certificateName,
                               bool crlCheck = true,
                               const String& purpose = String("any"));
        /**
         * Initialize the config file
         *
         * Copy the template to a configfile and create the config object
         */
        void initConfigFile();

        /**
         * Copy Config file to template
         */
        void commitConfig2Template();

        CAConfig* getConfig();


        /* ##########################################################################
         * ###          static Functions                                          ###
         * ##########################################################################
         */

        /**
         * Create a new selfsigned root CA and creates the
         * whole needed infrastructure.
         *
         * @param CertificateData the required certificate data
         *
         * @return true for success otherwise false
         */
        static bool 
        createRootCA(const String& caName,
                     const String& caPasswd,
                     const RequestGenerationData& caRequestData,
                     const CertificateIssueData& caIssueData,
                     const String& repos=REPOSITORY);
        

        /**
         * Import a CA certificate and private key and creates a 
         * infrastructure.
         *
         * @param caName the name of the CA
         * @param caCertificate the CA certificate data in PEM format
         * @param caKey the private key in PEM format
         * @param caPasswd a password for the private key, if caKey is unencrypted
         *
         * @return true on success, otherwise false
         */
        static bool
        importCA(const String& caName,
                 const String& caCertificate,
                 const String& caKey,
                 const String& caPasswd = String(),
                 const String& repos=REPOSITORY);

        /**
         * Get a list of available CAs
         *
         * @return StringList of available CAs
         */
        static blocxx::Array<blocxx::String> getCAList(const String& repos=REPOSITORY);
        
        /**
         * Get a list of lists of the available CAs 
         * containing the issuer caName.
         *
         * @return a list of lists of the available CAs 
         */
        static blocxx::List<blocxx::List<blocxx::String> >
        getCATree(const String& repos=REPOSITORY);

        /**
         * Get a CertificateIssueData object with current signing default
         * settings for a Root CA.
         *
         * @return a CertificateIssueData object with the current defaults
         */
        static CertificateIssueData  getRootCAIssueDefaults(const String& repos=REPOSITORY);

        /**
         * Get a RequestGenerationData object with current request default
         * settings for a Root CA.
         *
         * @return a RequestGenerationData object with the current defaults
         */
        static RequestGenerationData getRootCARequestDefaults(const String& repos=REPOSITORY);


        /**
         * Delete a Certificate Authority infrastructure
         *
         * Normaly you can only delete a CA if the CA certificate is expired or
         * you have never signed a certificate with this CA. In all other cases 
         * you have to set the force parameter to "true" if you realy want to delete 
         * the CA and you know what you are doing.
         *
         * @param caPasswd the password of the CA
         * @param force no checks, simply delete the CA
         *
         * @return true on success, otherwise false
         */
        static bool deleteCA(const String& caName,
                             const String& caPasswd,
                             bool force = false,
                             const String& repos = REPOSITORY);

    private:
        String caName;
        String caPasswd;
        String repositoryDir;

        CAConfig *config; 
        CAConfig *templ; 

        CA();
        CA(const CA&);

        CA& operator=(const CA&);

        /**
         * Check if the given dn matches the policy defined in the 
         * configuration file
         *
         * @param dn the DN object
         * @param type the Type of the certificate which should be signed
         *
         * @return empty String if the policy match, otherwise a error message
         */
        void checkDNPolicy(const DNObject& dn, Type type);

    };
    
}       // End of CA_MGM_NAMESPACE
}       // End of LIMAL_NAMESPACE

#endif  // LIMAL_CA_MGM_HPP

