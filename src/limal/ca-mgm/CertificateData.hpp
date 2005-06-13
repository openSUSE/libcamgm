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
        ByteArray      getPublicKey() const;
        SigAlg         getSignatureAlgorithm() const;
        String         getSignatureAlgorithmAsString() const;
        String         getSignature() const;
        String         getFingerprint() const;
        X509v3CertificateExtensions getExtensions() const;
                

    protected:
        CertificateData();

        blocxx::UInt32   version;
        String           serial;    // String?
        time_t           notBefore; // oder ein Date Object?
        time_t           notAfter;  // oder ein Date Object?

        DNObject         issuer;
        DNObject         subject;
        blocxx::UInt32   keysize;

        KeyAlg           pubkeyAlgorithm; // oder enum?

        // DER des public key
        //   man EVP_PKEY_set1_RSA
        //   man EVP_PKEY_get1_RSA
        //   man i2d_RSAPublicKey     => i2d == internal to DER
        //   man d2i_RSAPublicKey     => d2i == DER to internal
        ByteArray        publicKey;  

        SigAlg           signatureAlgorithm;
        String           signature;     // mit private key der CA verschlüsselter Hash wert
                                        // des Zertifikates


        X509v3CertificateExtensions extensions;

    };

}
}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
