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

  File:       LocalManagement.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP
#define    LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CertificateData.hpp>
#include  <limal/ca-mgm/RequestData.hpp>
#include  <limal/ca-mgm/CRLData.hpp>
#include  <limal/ByteBuffer.hpp>

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Functions for local certificate management
     *
     * This class provides functions for local certificate management which
     * are usefull on every host.
     */
    class LocalManagement {

    public:

        /**
         * Import a certificate to a specific destination
         *
         * @param pkcs12File full path to a PKCS12 file with the certificates
         * @param password the password for the PKCS12 file
         * @param destinationCAsDir path to the directory where the CAs are stored
         * @param destinationCertFile the path where the certificate should be stored
         * @param destinationKeyFile the path where the private key should be stored
         *
         */
        static void
        importAsLocalCertificate(const std::string &pkcs12File,
                                 const std::string &password,
                                 const std::string &destinationCAsDir,
                                 const std::string &destinationCertFile,
                                 const std::string &destinationKeyFile);

        /**
         * Import a certificate to a specific destination
         *
         * @param pkcs12Data PKCS12 certificate data
         * @param password the password for the PKCS12 file
         * @param destinationCAsDir path to the directory where the CAs are stored
         * @param destinationCertFile the path where the certificate should be stored
         * @param destinationKeyFile the path where the private key should be stored
         *
         */
        static void
        importAsLocalCertificate(const ca_mgm::ByteBuffer &pkcs12Data,
                                 const std::string            &password,
                                 const std::string            &destinationCAsDir,
                                 const std::string            &destinationCertFile,
                                 const std::string            &destinationKeyFile);

        /**
         * Import a certificate as common server certificate.
         * This function store the CAs to '/etc/ssl/certs', the
         * certificate to '/etc/ssl/servercerts/servercert.pem' and
         * the private key to '/etc/ssl/servercerts/serverkey.pem'.
         *
         * @param pkcs12File full path to a PKCS12 file with the certificates
         * @param password the password for the PKCS12 file
         *
         */
        static void
        importCommonServerCertificate(const std::string &pkcs12File,
                                      const std::string &password);

        /**
         * Import a certificate as common server certificate.
         * This function store the CAs to '/etc/ssl/certs', the
         * certificate to '/etc/ssl/servercerts/servercert.pem' and
         * the private key to '/etc/ssl/servercerts/serverkey.pem'.
         *
         * @param pkcs12Data PKCS12 certificate data
         * @param password the password for the PKCS12 file
         *
         */
        static void
        importCommonServerCertificate(const ca_mgm::ByteBuffer &pkcs12Data,
                                      const std::string            &password);

        /**
         * Parse a Certificate and return the data
         *
         * @param file path to the certificate file in PEM or DER format
         * @param type the format of the certificate
         *
         * @return the parsed certificate data
         */
        static CertificateData
        getCertificate(const std::string &file,
                       FormatType    type);

        /**
         * Parse a Certificate and return the data
         *
         * @param data the certificate data in PEM or DER format
         * @param type the format of the certificate
         *
         * @return the parsed certificate data
         */
        static CertificateData
        getCertificate(const ca_mgm::ByteBuffer &data,
                       FormatType               type);

        /**
         * Parse a Request and return the data
         *
         * @param file path to the request file in PEM or DER format
         * @param type the format of the request
         *
         * @return the parsed request data
         */
        static RequestData
        getRequest(const std::string &file,
                   FormatType    type);

        /**
         * Parse a Request and return the data
         *
         * @param data the request data in PEM or DER format
         * @param type the format of the request
         *
         * @return the parsed request data
         */
        static RequestData
        getRequest(const ca_mgm::ByteBuffer &data,
                   FormatType               type);


        /**
         * Parse a CRL and return the data
         *
         * @param file path to the CRL file in PEM or DER format
         * @param type the format of the CRL
         *
         * @return the parsed CRL data
         */
        static CRLData
        getCRL(const std::string &file,
               FormatType    type);


        /**
         * Parse a CRL and return the data
         *
         * @param data the CRL data in PEM or DER format
         * @param type the format of the CRL
         *
         * @return the parsed CRL data
         */
        static CRLData
        getCRL(const ca_mgm::ByteBuffer &data,
               FormatType               type);

        /**
         * Read a file from the harddisk and return
         * the content as ByteBuffer Object
         *
         * @param file the path to the file to read
         *
         * @return the file content
         */
        static ca_mgm::ByteBuffer
        readFile(const std::string& file);

        /**
         * Write data into a file
         *
         * @param data the data to write
         * @param file the path to the file
         * @param overwrite if this is true and the file exists it will
         * be overwritten with the new data, if false it throws an exception
         * @param mode the file permissions for the file (only if it is new created)
         *
         */
        static void
        writeFile(const ca_mgm::ByteBuffer& data,
                  const std::string &file,
                  bool overwrite = true,
                  mode_t mode = 0644);

    	/**
    	 * Convert a certificate from PEM/DER to DER/PEM format
    	 *
    	 * @param certificate the certificate in PEM or DER str::form
    	 * @param inform format of certificate
    	 * @param outform the output format
    	 * @return the converted certificate in the new format
    	 */
    	static ca_mgm::ByteBuffer
    	x509Convert(const ca_mgm::ByteBuffer &certificate,
    	            FormatType inform,
    	            FormatType outform );

    	/**
    	 * Convert a rsa key from PEM/DER to DER/PEM.
    	 * This function can also be used to set a new
    	 * password or remove the encryption from the key.
    	 * An encrypted key is only available if the format is PEM.
    	 *
    	 * @param key the key data
    	 * @param inform the format of the key data
    	 * @param outform the output format of the key
    	 * @param inPassword the password for the key data. "" == no password set.
    	 * @param outPassword the new password for the key. "" == no password for the new key.
    	 * @param algorithm the encryption algorithm for the key
    	 *        valid values are: des, des3, aes128, aes192, aes256
    	 * @return the converted key
    	 */
    	static ca_mgm::ByteBuffer
    	rsaConvert(const ca_mgm::ByteBuffer &key,
    	           FormatType inform,
    	           FormatType outform,
    	           const std::string &inPassword,
    	           const std::string &outPassword,
    	           const std::string &algorithm = "des3" );

    	/**
    	 * Convert a CRL from PEM/DER to DER/PEM format
    	 *
    	 * @param crl the CRL in PEM or DER format
    	 * @param inform the format of crl
    	 * @param outform the output format
    	 * @return the converted CRL
    	 */
    	static ca_mgm::ByteBuffer
    	crlConvert(const ca_mgm::ByteBuffer &crl,
    	           FormatType inform,
    	           FormatType outform );

    	/**
    	 * Convert a Request from PEM/DER to DER/PEM format
    	 *
    	 * @param req the Request in PEm or DER format
    	 * @param inform the format of req
    	 * @param outform the output format
    	 * @return the converted Request
    	 */
    	static ca_mgm::ByteBuffer
    	reqConvert(const ca_mgm::ByteBuffer &req,
    	           FormatType inform,
    	           FormatType outform );


    	/**
    	 * Create a PKCS12 bundle.
    	 * Certificate and key has to be in PEM format.
    	 *
    	 * @param certificate the certificate in PEM format
    	 * @param key the private key in PEM format
    	 * @param inPassword the password of key. If key is not encrypted
    	 *        use "".
    	 * @param outPassword the password of the pkcs12 file (empty not allowed)
    	 * @param caCert additional certificates to include in this container
    	 * @param caPath set the path to the CA store
    	 * @param withChain include the entire certificate chain of certificate
    	 * @return the PKCS12 file
    	 */
    	static ca_mgm::ByteBuffer
    	createPKCS12(const ca_mgm::ByteBuffer &certificate,
    	             const ca_mgm::ByteBuffer &key,
    	             const std::string            &inPassword,
    	             const std::string            &outPassword,
    	             const ca_mgm::ByteBuffer &caCert,
    	             const std::string            &caPath,
    	             bool                     withChain = false);

    	/**
    	 * Extract PKCS12 to PEM
    	 *
    	 * @param pkcs12 the PKCS12 file
    	 * @param inPassword the password of pkcs12
    	 * @param outPassword the new password for the private key.
    	 *        If outPasswort is "", the private key will not be encrypted.
    	 * @param algorithm the encryption algorithm for the key
    	 *        valid values are: des, des3, aes128, aes192, aes256
    	 * @return the certificates and private key
    	 */
    	static ca_mgm::ByteBuffer
    	pkcs12ToPEM(const ca_mgm::ByteBuffer &pkcs12,
    	            const std::string            &inPassword,
    	            const std::string            &outPassword,
    	            const std::string            &algorithm = "des3");
    };
}
#endif //LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP
