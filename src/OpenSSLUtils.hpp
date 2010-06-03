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

  File:       OpenSSLUtils.hpp

  Author:     Michael Calmer
  Maintainer: Michael Calmer
/-*/
/**
 * @file   OpenSSLUtils.hpp
 * @brief  This file is private for the ca-mgm library.
 *         It defines functions from openssl
 */
#ifndef   LIMAL_CA_MGM_OPENSSL_UTILS_HPP
#define   LIMAL_CA_MGM_OPENSSL_UTILS_HPP

#include <limal/ca-mgm/config.h>
#include <limal/ca-mgm/CommonData.hpp>
#include <limal/ca-mgm/DNObject.hpp>
#include <limal/ca-mgm/CRLReason.hpp>
#include <limal/ByteBuffer.hpp>

#include "Commands.hpp"


namespace CA_MGM_NAMESPACE {

class OpenSSLUtils {

public:

	OpenSSLUtils(const blocxx::String &onfigFile,
	             const blocxx::String &command = OPENSSL_COMMAND,
	             const blocxx::String &tmpDir = "/tmp/");

	void createRSAKey(const blocxx::String &outFile,
	                  const blocxx::String &password,
	                  blocxx::UInt32        bits = 2048,
	                  const blocxx::String &cryptAlgorithm = "des3");

	void createRequest(const DNObject       &dn,
	                   const blocxx::String &outFile,
	                   const blocxx::String &keyFile,
	                   const blocxx::String &password,
	                   const blocxx::String &extension,
	                   FormatType            outForm           = E_PEM,
	                   const blocxx::String &challengePassword = "",
	                   const blocxx::String &unstructuredName  = "");

	void createSelfSignedCertificate(const blocxx::String &outFile,
	                                 const blocxx::String &keyFile,
	                                 const blocxx::String &requestFile,
	                                 const blocxx::String &password,
	                                 const blocxx::String &extension,
	                                 const blocxx::UInt32  days,
	                                 bool                  noEmailDN = false);

	void signRequest(const blocxx::String &requestFile,
	                 const blocxx::String &outFile,
	                 const blocxx::String &caKeyFile,
	                 const blocxx::String &caPassword,
	                 const blocxx::String &extension,
	                 const blocxx::String &startDate,
	                 const blocxx::String &endDate,
	                 const blocxx::String &caSection,
	                 const blocxx::String &outDir     = "",
	                 bool                  noEmailDN  = false,
	                 bool                  noUniqueDN = false,
	                 bool                  noText     = true);

	void revokeCertificate(const blocxx::String &caCertFile,
	                       const blocxx::String &caKeyFile,
	                       const blocxx::String &caPassword,
	                       const blocxx::String &certFile,
	                       const CRLReason      &reason     = CRLReason(),
	                       bool                  noUniqueDN = false);

	void issueCRL(const blocxx::String &caCertFile,
	              const blocxx::String &caKeyFile,
	              const blocxx::String &caPassword,
	              blocxx::UInt32        hours,
	              const blocxx::String &outfile,
	              const blocxx::String &extension,
	              bool                  noUniqueDN = false);

	void updateDB(const blocxx::String &caCertFile,
	              const blocxx::String &caKeyFile,
	              const blocxx::String &caPassword);

	blocxx::String verify(const blocxx::String &certFile,
	                      const blocxx::String &caPath,
	                      bool                  crlCheck = false,
	                      const blocxx::String &purpose  = "");

	blocxx::String status(const blocxx::String &serial);

	bool checkKey(const blocxx::String &caName,
	              const blocxx::String &password,
	              const blocxx::String &certificateName = "cacert",
	              const blocxx::String &repository      = REPOSITORY);


		// ###################################################
		// ### static functions
		// ###################################################

	static ByteBuffer
	x509Convert(const ByteBuffer &certificate,
	            FormatType inform,
	            FormatType outform );

	static ByteBuffer
	rsaConvert(const ByteBuffer &key,
	           FormatType inform,
	           FormatType outform,
	           const String &inPassword,
	           const String &outPassword,
	           const String &algorithm = "des3" );

	static ByteBuffer
	crlConvert(const ByteBuffer &crl,
	           FormatType inform,
	           FormatType outform );

	static ByteBuffer
	reqConvert(const ByteBuffer &req,
	           FormatType inform,
	           FormatType outform );

		/**
         * certificate and key has to be in PEM format
         */
	static ByteBuffer
	createPKCS12(const ByteBuffer &certificate,
	             const ByteBuffer &key,
	             const String     &inPassword,
	             const String     &outPassword,
	             const ByteBuffer &caCert,
	             const String     &caPath,
	             bool              withChain );

		/**
         * PKCS12 => PEM format
         */
	static ByteBuffer
	pkcs12ToPEM(const ByteBuffer &pkcs12,
	            const String     &inPassword,
	            const String     &outPassword,
	            const String     &algorithm = "des3");

	static blocxx::Array<blocxx::String>
	listCA(const String &repository = REPOSITORY);

	static blocxx::String
	nextSerial(const String &serialFile);

	static void
	addCAM(const String &caName,
	       const String &md5,
	       const String &dnString,
	       const String &repository = REPOSITORY);

	static void
	delCAM(const String &caName,
	       const String &md5,
	       const String &repository = REPOSITORY);

	static blocxx::Array<blocxx::Array<blocxx::String> >
	parseCAMDB(const String &caName,
	           const String &repository = REPOSITORY);

	static blocxx::Array<blocxx::Array<blocxx::String> >
	parseIndexTXT(const String &caName,
	              const String &repository = REPOSITORY);

	static blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
	listRequests(const String &caName,
	             const String &repository = REPOSITORY);

	static blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
	listCertificates(const String &caName,
	                 const String &repository = REPOSITORY);

	static void
	createCaInfrastructure(const String &caName,
	                       const String &repository = REPOSITORY);

private:

	blocxx::String   m_cmd;
	blocxx::String   m_tmp;
	blocxx::String   m_conf;
	blocxx::String   m_rand;

	OpenSSLUtils();
	OpenSSLUtils(const OpenSSLUtils&);

	OpenSSLUtils& operator=(const OpenSSLUtils&);

};
}

#endif // LIMAL_CA_MGM_OPENSSL_UTILS_HPP
