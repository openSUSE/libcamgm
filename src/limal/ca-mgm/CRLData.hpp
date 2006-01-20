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
#include  <limal/ByteBuffer.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class RevocationEntry {
    public:
        RevocationEntry();
        RevocationEntry(const RevocationEntry& entry);
        virtual ~RevocationEntry();
        
        RevocationEntry&
        operator=(const RevocationEntry& entry);

        String
        getSerial() const;

        time_t
        getRevocationDate() const;
        
        CRLReason
        getReason() const;

        virtual bool
        valid() const;
        
        virtual blocxx::StringArray
        verify() const;

        virtual blocxx::StringArray
        dump() const;

    protected:

        String      serial;
        time_t      revocationDate;
        CRLReason   revocationReason;

    };

    /**
     * @brief Read-only data representation of a CRL
     *
     * This class is a read-only data representation of a CRL.
     */
    class CRLData {
    public:
        CRLData(const CRLData& data);
        virtual ~CRLData();

        CRLData&
        operator=(const CRLData& data);

        blocxx::Int32
        getVersion() const;
        
		String
		getFingerprint() const;
		
		time_t
		getLastUpdateDate() const;
        
        time_t
        getNextUpdateDate() const;
        
        DNObject
        getIssuerDN() const;
        
        SigAlg
        getSignatureAlgorithm() const;
        
        String
        getSignatureAlgorithmAsString() const;
        
        limal::ByteBuffer
        getSignature() const;
        
        X509v3CRLExts
        getExtensions() const;
        
        blocxx::Map<String, RevocationEntry>
        getRevocationData() const;
        
        RevocationEntry
        getRevocationEntry(const String& oid);

    	/**
    	 * Return the CRL data as human readable text.
    	 * (Format may change)
    	 */
    	String
    	getCRLAsText() const;

    	/**
    	 * Return the CRL extensions as human readable text.
    	 * (Format may change)
    	 */
    	String
    	getExtensionsAsText() const;
    	
        virtual bool
        valid() const;
        
        virtual blocxx::StringArray
        verify() const;

        virtual blocxx::StringArray
        dump() const;

    protected:
        CRLData();

        blocxx::Int32                        version;
		String                               fingerprint;
        time_t                               lastUpdate;
        time_t                               nextUpdate;

        DNObject                             issuer;

        SigAlg                               signatureAlgorithm;
        ByteBuffer                           signature;    
        
        X509v3CRLExts                        extensions;

        blocxx::Map<String, RevocationEntry> revocationData;

    	String                               text;
    	String                               extText;

    	
        blocxx::StringArray
        checkRevocationData(const blocxx::Map<String, RevocationEntry>& rd) const;

    };

}
}

#endif // LIMAL_CA_MGM_CRL_DATA_HPP
