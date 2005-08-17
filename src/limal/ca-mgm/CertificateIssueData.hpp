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

  File:       CertificateIssueData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATAHPP
#define    LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATAHPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/X509v3CertificateIssueExtensions.hpp>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

    /**
     * @brief Data representation for signing a certificate
     *
     * This class is a data representation for signing a certificate
     */
    class CertificateIssueData {
    public:
        CertificateIssueData();

        /**
         * Initialize this object with the defaults of the CA 
         * and Type
         */
        CertificateIssueData(CAConfig* caConfig, Type type);

        CertificateIssueData(const CertificateIssueData& data);

        virtual ~CertificateIssueData();

        CertificateIssueData& operator=(const CertificateIssueData& data);

        void           setCertifiyPeriode(time_t start, time_t end);
        time_t         getStartDate() const;
        time_t         getEndDate() const;
        blocxx::String getStartDateAsString() const;
        blocxx::String getEndDateAsString() const;

        void           setMessageDigest(MD md);
        MD             getMessageDigest() const;

        void           setExtensions(const X509v3CertificateIssueExtensions& ext);
        X509v3CertificateIssueExtensions getExtensions() const;

        /** 
         * Write memory data to config file
         */
        void           commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        time_t           notBefore;
        time_t           notAfter;

        // ???  KeyAlg           pubkeyAlgorithm; // at the beginning we only support rsa


        MD               messageDigest;           // parameter default_md

        X509v3CertificateIssueExtensions extensions;

    };

}
}
#endif //LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATA_HPP
