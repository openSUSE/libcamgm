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

	OpenSSLUtils(const std::string &onfigFile,
	             const std::string &command = OPENSSL_COMMAND,
	             const std::string &tmpDir = "/tmp/");

	void createRSAKey(const std::string &outFile,
	                  const std::string &password,
	                  uint32_t        bits = 2048,
	                  const std::string &cryptAlgorithm = "des3");

	void createRequest(const std::string &outFile,
	                   const std::string &keyFile,
	                   const std::string &password,
	                   const std::string &extension,
	                   FormatType         outForm = E_PEM);

	void createSelfSignedCertificate(const std::string &outFile,
	                                 const std::string &keyFile,
	                                 const std::string &requestFile,
	                                 const std::string &password,
	                                 const std::string &extension,
	                                 const uint32_t  days,
	                                 bool                  noEmailDN = false);

	void signRequest(const std::string &requestFile,
	                 const std::string &outFile,
	                 const std::string &caKeyFile,
	                 const std::string &caPassword,
	                 const std::string &extension,
	                 const std::string &startDate,
	                 const std::string &endDate,
	                 const std::string &caSection,
	                 const std::string &outDir     = "",
	                 bool                  noEmailDN  = false,
	                 bool                  noUniqueDN = false,
	                 bool                  noText     = true);

	void revokeCertificate(const std::string &caCertFile,
	                       const std::string &caKeyFile,
	                       const std::string &caPassword,
	                       const std::string &certFile,
	                       const CRLReason      &reason     = CRLReason(),
	                       bool                  noUniqueDN = false);

	void issueCRL(const std::string &caCertFile,
	              const std::string &caKeyFile,
	              const std::string &caPassword,
	              uint32_t        hours,
	              const std::string &outfile,
	              const std::string &extension,
	              bool                  noUniqueDN = false);

	void updateDB(const std::string &caCertFile,
	              const std::string &caKeyFile,
	              const std::string &caPassword);

	std::string verify(const std::string &certFile,
	                      const std::string &caPath,
	                      bool                  crlCheck = false,
	                      const std::string &purpose  = "");

	std::string status(const std::string &serial);

	bool checkKey(const std::string &caName,
	              const std::string &password,
	              const std::string &certificateName = "cacert",
	              const std::string &repository      = REPOSITORY);


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
	           const std::string &inPassword,
	           const std::string &outPassword,
	           const std::string &algorithm = "des3" );

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
	             const std::string     &inPassword,
	             const std::string     &outPassword,
	             const ByteBuffer &caCert,
	             const std::string     &caPath,
	             bool              withChain );

		/**
         * PKCS12 => PEM format
         */
	static ByteBuffer
	pkcs12ToPEM(const ByteBuffer &pkcs12,
	            const std::string     &inPassword,
	            const std::string     &outPassword,
	            const std::string     &algorithm = "des3");

	static std::vector<std::string>
	listCA(const std::string &repository = REPOSITORY);

	static std::string
	nextSerial(const std::string &serialFile);

	static void
	addCAM(const std::string &caName,
	       const std::string &md5,
	       const std::string &dnString,
	       const std::string &repository = REPOSITORY);

	static void
	delCAM(const std::string &caName,
	       const std::string &md5,
	       const std::string &repository = REPOSITORY);

	static std::vector<std::vector<std::string> >
	parseCAMDB(const std::string &caName,
	           const std::string &repository = REPOSITORY);

	static std::vector<std::vector<std::string> >
	parseIndexTXT(const std::string &caName,
	              const std::string &repository = REPOSITORY);

	static std::vector<std::map<std::string, std::string> >
	listRequests(const std::string &caName,
	             const std::string &repository = REPOSITORY);

	static std::vector<std::map<std::string, std::string> >
	listCertificates(const std::string &caName,
	                 const std::string &repository = REPOSITORY);

	static void
	createCaInfrastructure(const std::string &caName,
	                       const std::string &repository = REPOSITORY);

    static std::string
    digestMD5(const std::string &in);

private:

	std::string   m_cmd;
	std::string   m_tmp;
	std::string   m_conf;
	std::string   m_rand;

	OpenSSLUtils();
	OpenSSLUtils(const OpenSSLUtils&);

	OpenSSLUtils& operator=(const OpenSSLUtils&);

};
}

#endif // LIMAL_CA_MGM_OPENSSL_UTILS_HPP
