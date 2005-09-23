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

  File:       CertificateData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CertificateExtensions.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ByteBuffer.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Read-only data representation of a certificate
     *
     * This class is a read-only data representation of a certificate
     */
    class CertificateData {
    public:
        CertificateData(const CertificateData& data);

        virtual ~CertificateData();

        CertificateData& operator=(const CertificateData& data);

        blocxx::UInt32 getVersion() const;
        String         getSerial() const;
        time_t         getStartDate() const;
        time_t         getEndDate() const;
        DNObject       getIssuerDN() const;
        DNObject       getSubjectDN() const;
        blocxx::UInt32 getKeysize() const;
        KeyAlg         getPublicKeyAlgorithm() const;
        String         getPublicKeyAlgorithmAsString() const;
        limal::ByteBuffer getPublicKey() const;
        SigAlg         getSignatureAlgorithm() const;
        String         getSignatureAlgorithmAsString() const;
        limal::ByteBuffer getSignature() const;
        String         getFingerprint() const;
        X509v3CertificateExtensions getExtensions() const;
                
        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    protected:
        CertificateData();

        blocxx::UInt32   version;   // allowed 1, 2, 3
        String           serial;    
        time_t           notBefore; 
        time_t           notAfter;  

        DNObject         issuer;
        DNObject         subject;
        blocxx::UInt32   keysize;

        KeyAlg           pubkeyAlgorithm; 

        ByteBuffer       publicKey;  

        SigAlg           signatureAlgorithm;
        ByteBuffer       signature;     
                                         // mit private key der CA verschlüsselter Hash wert
                                         // des Zertifikates


        X509v3CertificateExtensions extensions;

    };

}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
