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

  File:       CRLData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DATA_HPP
#define    LIMAL_CA_MGM_CRL_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CRLReason.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ca-mgm/X509v3CRLExtensions.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class RevokationEntry {
    public:
        RevokationEntry();
        RevokationEntry(const String&    serial, 
                        time_t           revokeDate,
                        const CRLReason& reason);
        RevokationEntry(const RevokationEntry& entry);
        virtual ~RevokationEntry();
        
        RevokationEntry& operator=(const RevokationEntry& entry);

        void        setSerial(const String& serial);
        void        setRevokationDate(time_t date);
        void        setReason(const CRLReason& reason);

        String      getSerial() const;
        time_t      getRevokationDate() const;
        CRLReason   getReason() const;


    private:

        String      serial;
        time_t      revokationDate;
        CRLReason   revokationReason;

    };

    /**
     * @brief Read-only data representation of a CRL
     *
     * This class is a read-only data representation of a CRL.
     */
    class CRLData {
    public:
        virtual ~CRLData();

        blocxx::Int32                getVersion() const;
        time_t                       getLastUpdateDate() const;
        time_t                       getNextUpdateDate() const;
        DNObject                     getIssuerDN() const;
        SigAlg                       getSignatureAlgorithm() const;
        String                       getSignatureAlgorithmAsString() const; 
        String                       getSignature() const;
        X509v3CRLExtensions          getExtensions() const;
        blocxx::Map<String, RevokationEntry> getRevokationData() const;
        RevokationEntry              getRevokationEntry(const String& oid);

    protected:
        CRLData();

        blocxx::Int32    version;
        time_t           lastUpdate;
        time_t           nextUpdate;

        DNObject         issuer;

        SigAlg           signatureAlgorithm;
        String           signature;     // mit private key der CA verschlüsselter Hash wert
                                        // des Zertifikates
        
        X509v3CRLExtensions extensions;

        //RevokationData   revokationData;
        blocxx::Map<String, RevokationEntry> revokationData;

    private:
        CRLData(const CRLData& data);

        CRLData& operator=(const CRLData& data);
    };

}
}

#endif // LIMAL_CA_MGM_CRL_DATA_HPP
