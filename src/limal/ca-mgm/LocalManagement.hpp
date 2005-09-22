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

namespace LIMAL_NAMESPACE {

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
        importAsLocalCertificate(const String &pkcs12File,
                                 const String &password,
                                 const String &destinationCAsDir,
                                 const String &destinationCertFile,
                                 const String &destinationKeyFile);
        
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
        importAsLocalCertificate(const limal::ByteBuffer &pkcs12Data,
                                 const String            &password,
                                 const String            &destinationCAsDir,
                                 const String            &destinationCertFile,
                                 const String            &destinationKeyFile);

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
        importCommonServerCertificate(const String &pkcs12File,
                                      const String &password);
        
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
        importCommonServerCertificate(const limal::ByteBuffer &pkcs12File,
                                      const String            &password);
        
        /**
         * Parse a Certificate and return the data
         *
         * @param file path to the certificate file in PEM or DER format
         * @param type the format of the certificate
         *
         * @return the parsed certificate data
         */
        static CertificateData
        getCertificate(const String &file,
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
        getCertificate(const limal::ByteBuffer &data,
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
        getRequest(const String &file,
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
        getRequest(const limal::ByteBuffer &data,
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
        getCRL(const String &file,
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
        getCRL(const limal::ByteBuffer &data,
               FormatType               type);
        
        /**
         * Read a file from the harddisk and return
         * the content as ByteBuffer Object
         *
         * @param file the path to the file to read
         *
         * @return the file content
         */
        static limal::ByteBuffer
        readFile(const String& file);

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
        writeFile(const limal::ByteBuffer& data,
                  const String &file,
                  bool overwrite = true,
                  mode_t mode = 0644);
    };
}
}
#endif //LIMAL_CA_MGM_LOCAL_MANAGEMENT_HPP
