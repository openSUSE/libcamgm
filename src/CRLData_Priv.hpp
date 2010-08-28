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

  File:       CRLData_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DATA_PRIV_HPP
#define    LIMAL_CA_MGM_CRL_DATA_PRIV_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/CRLData.hpp>
#include  <ca-mgm/ByteBuffer.hpp>

#include  <openssl/x509.h>


namespace CA_MGM_NAMESPACE {

class RevocationEntry_Priv : public RevocationEntry {
public:
	RevocationEntry_Priv();
	RevocationEntry_Priv(X509_REVOKED *rev);
	RevocationEntry_Priv(const std::string&    serial,
	                     time_t           revokeDate,
	                     const CRLReason& reason);
	RevocationEntry_Priv(const RevocationEntry_Priv& entry);
	virtual ~RevocationEntry_Priv();

	RevocationEntry_Priv& operator=(const RevocationEntry_Priv& entry);

	void        setSerial(const std::string& serial);

	void        setRevocationDate(time_t date);
	void        setReason(const CRLReason& reason);

};

class CRLData_Priv : public CRLData {
public:
	CRLData_Priv();
	CRLData_Priv(const ByteBuffer &crl,
	             FormatType formatType = E_PEM);
	CRLData_Priv(const std::string &crlPath,
	             FormatType formatType = E_PEM);
	CRLData_Priv(const CRLData_Priv& data);
	virtual ~CRLData_Priv();

	void
	setVersion(int32_t version);

	void
	setFingerprint(const std::string& fp);

	void
	setValidityPeriod(time_t last,
	                  time_t next);

	void
	setIssuerDN(const DNObject& issuer);

	void
	setSignatureAlgorithm(SigAlg sigAlg);

	void
	setSignature(const ByteBuffer& sig);

	void
	setExtensions(const X509v3CRLExts& ext);

	void
	setRevocationData(const std::map<std::string, RevocationEntry>& data);

private:
	CRLData_Priv& operator=(const CRLData_Priv& data);

	void   parseCRL(X509_CRL *x509);
	void   init(const ByteBuffer &crl, FormatType formatType);

};

}

#endif // LIMAL_CA_MGM_CRL_DATA_PRIV_HPP
