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

  File:       CA.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/LocalManagement.hpp>
#include  <limal/Exception.hpp>
#include  <limal/PathUtils.hpp>
#include  <limal/PathInfo.hpp>
#include  <blocxx/MD5.hpp>
#include  <limal/Date.hpp>
#include  <limal/String.hpp>
#include  <blocxx/StringBuffer.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  <openssl/pem.h>

#include  "CertificateData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "DNObject_Priv.hpp"
#include  "OpenSSLUtils.hpp"

#include  "Utils.hpp"
#include  "Commands.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class CAImpl : public blocxx::COWIntrusiveCountableBase
{
public:

	CAImpl(const std::string& caName, const std::string& caPasswd, const std::string& repos)
		: caName(caName)
		, caPasswd(caPasswd)
		, repositoryDir(repos)
		, config(NULL)
		, templ(NULL)
	{}

	~CAImpl()
	{

		if(config)
		{
			delete config;
			config = NULL;
		}
		if(templ)
		{
			delete templ;
			templ = NULL;
		}
	}

	CAImpl* clone() const
	{
		return new CAImpl(*this);
	}

	std::string
		initConfigFile()
	{
		if(templ)
		{
			if(config)
			{
				delete config;
				config = NULL;
			}
			config = templ->clone(repositoryDir + "/" + caName + "/openssl.cnf");
			return config->filename();
		}
		else
		{
			LOGIT_ERROR("template not initialized");
			// exception
			BLOCXX_THROW(ca_mgm::RuntimeException, __("Template not initialized."));
		}
		return "";
	}

	std::string caName;
	std::string caPasswd;
	std::string repositoryDir;

	CAConfig *config;
	CAConfig *templ;

private:
	CAImpl() {}
	CAImpl(const CAImpl &impl)
		: COWIntrusiveCountableBase(impl)
	{}
	CAImpl& operator=(const CAImpl &) { return *this; }

};

class CATreeCompare
{
public:
	int operator()(const std::vector<std::string> &l,
	               const std::vector<std::string> r) const
	{
		if(l.back() == "" && r.back() != "")
		{
			return true;
		}
		else if(l.back() != "" && r.back() == "")
		{
			return false;
		}
		else if(l.back() == r.back())
		{
			return l.front() < r.front();
		}
		else if(l.back() == r.front())
		{
			return false;
		}
		else if(l.front() == r.back())
		{
			return true;
		}
		return l.front() < r.front();
	}
};


CA::CA(const std::string& caName, const std::string& caPasswd, const std::string& repos)
{

	if(caName.empty())
	{
		LOGIT_ERROR("Empty CA name.");
		BLOCXX_THROW(ca_mgm::ValueException, __("Empty CA name."));
	}

	path::PathInfo pi(repos+"/"+caName+"/openssl.cnf.tmpl");
	if(!pi.exists())
	{
		LOGIT_ERROR("Template does not exists: " << pi.toString());
		BLOCXX_THROW_ERR(ca_mgm::SystemException,
		                 str::form(__("Template does not exist: %s."), pi.toString().c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	OpenSSLUtils ost(pi.toString());

	bool passOK = ost.checkKey(caName, caPasswd, "cacert", repos);

	if(!passOK)
	{
		LOGIT_ERROR("Invalid CA password");
		BLOCXX_THROW_ERR(ca_mgm::ValueException,
		                 __("Invalid CA password."), E_INVALID_PASSWD);
	}

	m_impl = new CAImpl(caName, caPasswd, repos);

	m_impl->templ = new CAConfig(repos+"/"+caName+"/openssl.cnf.tmpl");
}

CA::~CA()
{
	if(m_impl->config)
	{
		path::PathInfo pi(m_impl->config->filename());
		if(pi.exists())
		{
			int r = path::removeFile(m_impl->config->filename());

			if(r != 0)
			{
				LOGIT_INFO("Remove of openssl.cnf failed: " << r);
			}
		}
	}
}

std::string
CA::createSubCA(const std::string& newCaName,
                const std::string& keyPasswd,
                const RequestGenerationData& caRequestData,
                const CertificateIssueData& caIssueData)
{

	std::string certificate = createCertificate(keyPasswd,
	                                       caRequestData,
	                                       caIssueData,
	                                       E_CA_Cert);


	try
	{
		OpenSSLUtils::createCaInfrastructure(newCaName, m_impl->repositoryDir);
	}
	catch(blocxx::Exception &e)
	{
		LOGIT_ERROR(e);
		BLOCXX_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Error while creating the CA infrastructure."),
		                   e);
	}
	std::string request;

	PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
	std::vector<std::string> sa = p.capture(certificate);

	if(sa.size() == 3)
	{
		request = sa[2];
	}
	else
	{
		// cleanup
		path::removeDirRecursive(m_impl->repositoryDir + "/" + newCaName);

		LOGIT_ERROR("Can not parse certificate name: " << certificate);
		// %1 is the name of the CA
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             str::form(__("Cannot parse the certificate name %s."), certificate.c_str()).c_str());
	}

	int r = path::copyFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" + request + ".key",
	                       m_impl->repositoryDir + "/" + newCaName + "/cacert.key");
	if(r != 0)
	{
		// cleanup
		path::removeDirRecursive(m_impl->repositoryDir + "/" + newCaName);

		LOGIT_ERROR("Can not copy the private key." << r);
		BLOCXX_THROW(ca_mgm::SystemException, __("Cannot copy the private key."));
	}

	r = path::copyFile(m_impl->repositoryDir +"/"+ m_impl->caName +"/newcerts/"+ certificate +".pem",
	                   m_impl->repositoryDir +"/"+ newCaName +"/cacert.pem");
	if(r != 0)
	{
		// cleanup
		path::removeDirRecursive(m_impl->repositoryDir + "/" + newCaName);

		LOGIT_ERROR("Can not copy the certificate." << r);
		BLOCXX_THROW(ca_mgm::SystemException, __("Cannot copy the certificate."));
	}

	r = path::copyFile(m_impl->repositoryDir + "/" + newCaName + "/" + "cacert.pem",
	                   m_impl->repositoryDir + "/" + ".cas/" + newCaName + ".pem");

	if(r != 0)
	{
		LOGIT_INFO("Copy of cacert.pem to .cas/ failed: " << r);
	}

	rehashCAs(m_impl->repositoryDir + "/.cas/");

	// write DN defaults
	CA tmpCA = CA(newCaName, keyPasswd, m_impl->repositoryDir);
	tmpCA.initConfigFile();
	DNObject_Priv dnp( caRequestData.getSubjectDN() );
	dnp.setDefaults2Config(tmpCA);
	tmpCA.commitConfig2Template();

	return certificate;
}


std::string
CA::createRequest(const std::string& keyPasswd,
                  const RequestGenerationData& requestData,
                  Type requestType)
{
	if(!requestData.valid())
	{
		LOGIT_ERROR("Invalid request data");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid request data."));
	}

	// copy template to config
	std::string configFilename = initConfigFile();

	removeDefaultsFromConfig();

	OpenSSLUtils ost(configFilename);

	std::string opensslDN = requestData.getSubjectDN().getOpenSSLString();
	std::string request = OpenSSLUtils::digestMD5(opensslDN) + "-" +
		str::numstring(Date::now());

	path::PathInfo dKey(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/"+ request + ".key");
	if(dKey.exists())
	{
		LOGIT_ERROR("Duplicate DN. Key '" << request <<".key' already exists.");
		BLOCXX_THROW(RuntimeException,
		             str::form(__("Duplicate DN. Key %s.key already exists."), request.c_str()).c_str());
	}

	path::PathInfo r(m_impl->repositoryDir + "/" + m_impl->caName + "/req/"+ request + ".req");
	if(r.exists())
	{
		LOGIT_ERROR("Duplicate DN. Request '" << request <<".req' already exists.");
		BLOCXX_THROW(RuntimeException,
		             str::form(__("Duplicate DN. Request %s.req already exists."), request.c_str()).c_str());
	}

	// write request data to config
	requestData.commit2Config(*this, requestType);

	// copy Section, because "req" is hard coded in openssl :-(
	m_impl->config->copySection(type2Section(requestType, false), "req");

	// create key

	ost.createRSAKey(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/"+ request + ".key",
	                 keyPasswd, requestData.getKeysize());


	// create request

	ost.createRequest(requestData.getSubjectDN(),
	                  m_impl->repositoryDir + "/" + m_impl->caName + "/req/"+ request + ".req",
	                  m_impl->repositoryDir + "/" + m_impl->caName + "/keys/"+ request + ".key",
	                  keyPasswd,
	                  type2Section(requestType, true),
	                  E_PEM,
	                  requestData.getChallengePassword(),
	                  requestData.getUnstructuredName());


	OpenSSLUtils::addCAM(m_impl->caName, request, opensslDN, m_impl->repositoryDir);

	return request;
}


std::string
CA::issueCertificate(const std::string& requestName,
                     const CertificateIssueData& issueData,
                     Type certType)
{
	std::string requestFile = std::string(m_impl->repositoryDir + "/" + m_impl->caName + "/req/"+ requestName + ".req");
	path::PathInfo p(requestFile);
	if(!p.exists())
	{
		LOGIT_ERROR("Request does not exist.(" << requestFile << ")");
		// %1 is the absolute path to the request
		BLOCXX_THROW(ValueException,
		             str::form(__("Request does not exist (%s)."), requestFile.c_str() ).c_str());
	}

	if(!issueData.valid())
	{
		LOGIT_ERROR("Invalid issue data");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid issue data."));
	}

	std::string serial = OpenSSLUtils::nextSerial(m_impl->repositoryDir + "/" + m_impl->caName + "/serial");
	std::string certificate = serial + ":" + requestName;

	// parse the CA and check if the end date of the ca is greater
	// than the end date of the certificate

	CertificateData cdata = getCA();

	if(issueData.getEndDate() > cdata.getEndDate())
	{
		LOGIT_ERROR("CA expires before the certificate should expire.");
		LOGIT_ERROR("CA expires: '" << cdata.getEndDate() <<
		            "' Cert should expire: '" << issueData.getEndDate()<< "'");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("The CA expires before the certificate should expire."));
	}

	// Check the DN Policy
	RequestData rdata = getRequest(requestName);

	checkDNPolicy(rdata.getSubjectDN(), certType);

	// copy template to config
	std::string configFilename = initConfigFile();

	// write data to config
	issueData.commit2Config(*this, certType);

	OpenSSLUtils ost(configFilename);

	ost.signRequest(m_impl->repositoryDir + "/" + m_impl->caName + "/req/"+ requestName + ".req",
	                m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" + certificate + ".pem",
	                m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key",
	                m_impl->caPasswd,
	                type2Section(certType, true),
	                issueData.getStartDateAsString(),
	                issueData.getEndDateAsString(),
	                type2Section(certType, false),
	                m_impl->repositoryDir + "/" + m_impl->caName + "/certs/");

	return certificate;
}

std::string
CA::createCertificate(const std::string& keyPasswd,
                      const RequestGenerationData& requestData,
                      const CertificateIssueData&  certificateData,
                      Type type)
{
	Type t = E_Client_Req;

	if(type == E_Client_Req || type == E_Client_Cert)
	{
		t = E_Client_Req;
	}
	if(type == E_Server_Req || type == E_Server_Cert)
	{
		t = E_Server_Req;
	}
	if(type == E_CA_Req || type == E_CA_Cert)
	{
		t = E_CA_Req;
	}

	std::string requestName = createRequest(keyPasswd, requestData, t);

	if(type == E_Client_Req || type == E_Client_Cert)
	{
		t = E_Client_Cert;
	}
	if(type == E_Server_Req || type == E_Server_Cert)
	{
		t = E_Server_Cert;
	}
	if(type == E_CA_Req || type == E_CA_Cert)
	{
		t = E_CA_Cert;
	}

	std::string certificate;

	try
	{
		certificate = issueCertificate(requestName, certificateData, t);
	}
	catch(blocxx::Exception &e)
	{
		OpenSSLUtils::delCAM(m_impl->caName, requestName, m_impl->repositoryDir);

		path::removeFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" + requestName + ".key");
		path::removeFile(m_impl->repositoryDir + "/" + m_impl->caName + "/req/" + requestName + ".req");
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Issuing the certificate failed."), e);
	}

	return certificate;
}

void
CA::revokeCertificate(const std::string& certificateName,
                      const CRLReason& crlReason)
{
	path::PathInfo pi(m_impl->repositoryDir + "/" +
	                  m_impl->caName + "/newcerts/" +
	                  certificateName + ".pem");
	if(!pi.exists())
	{
		LOGIT_ERROR("File '" << certificateName << ".pem' not found in repository");
		BLOCXX_THROW_ERR(ca_mgm::SystemException,
		                 str::form(__("File %s not found in the repository."), certificateName.c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	if(!crlReason.valid())
	{
		LOGIT_ERROR("Invalid CRL reason");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid CRL reason."));
	}

	// copy template to config
	std::string configFilename = initConfigFile();

	OpenSSLUtils ost(configFilename);

	ost.revokeCertificate(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem",
	                      m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key",
	                      m_impl->caPasswd,
	                      m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" +
	                      certificateName + ".pem",
	                      crlReason);
}


void
CA::createCRL(const CRLGenerationData& crlData)
{
	if(!crlData.valid())
	{
		LOGIT_ERROR("Invalid CRL data");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid CRL data."));
	}

	// copy template to config
	std::string configFilename = initConfigFile();

	// write crl data to config
	crlData.commit2Config(*this, E_CRL);

	OpenSSLUtils ost(configFilename);

	ost.issueCRL(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem",
	             m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key",
	             m_impl->caPasswd,
	             crlData.getCRLLifeTime(),
	             m_impl->repositoryDir + "/" + m_impl->caName + "/crl/crl.pem",
	             "v3_crl");

	int r = path::copyFile(m_impl->repositoryDir + "/" + m_impl->caName + "/crl/crl.pem",
	                       m_impl->repositoryDir + "/" + ".cas/crl_" + m_impl->caName + ".pem");

	if(r != 0)
	{
		LOGIT_INFO("Copy of crl.pem to .cas/ failed: " << r);
	}

	rehashCAs(m_impl->repositoryDir + "/.cas/");
}

std::string
CA::importRequestData(const ByteBuffer& request,
                      FormatType formatType)
{
	RequestData rd = RequestData_Priv(request, formatType);

	std::string name = rd.getSubjectDN().getOpenSSLString();

	std::string requestName = OpenSSLUtils::digestMD5(name) + "-" +
		str::numstring(Date::now());

	path::PathInfo outPi(m_impl->repositoryDir + "/" + m_impl->caName + "/req/" + requestName + ".req");

	if(outPi.exists())
	{
		LOGIT_ERROR("Duplicate DN. Request already exists.");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("Duplicate DN. Request already exists."));
	}

	if(formatType == E_PEM)
	{
		LocalManagement::writeFile(request, outPi.toString());
	}
	else
	{
		// we have to convert the request to PEM format
#if OPENSSL_VERSION_NUMBER >= 0x0090801fL
		const unsigned char *dbuf = (const unsigned char*)request.data();
#else
		unsigned char *dbuf = (unsigned char*)request.data();
#endif

		X509_REQ *req  = NULL;

		req=d2i_X509_REQ(NULL, &dbuf , request.size());

		char *pbuf = NULL;
		BIO  *bio  = BIO_new(BIO_s_mem());
		PEM_write_bio_X509_REQ(bio , req);
		int k = BIO_get_mem_data(bio, &pbuf);

		ByteBuffer d(pbuf, k);
		LocalManagement::writeFile(d, outPi.toString());

		BIO_free(bio);
		X509_REQ_free(req);
	}

	OpenSSLUtils::addCAM(m_impl->caName, requestName, name, m_impl->repositoryDir);

	return requestName;
}

std::string
CA::importRequest(const std::string& requestFile,
                  FormatType formatType)
{
	ByteBuffer ba = LocalManagement::readFile(requestFile);

	return importRequestData(ba, formatType);
}

CertificateIssueData
CA::getIssueDefaults(Type type)
{
	initConfigFile();
	CertificateIssueData cid = CertificateIssueData(m_impl->config, type);
	return cid;
}

RequestGenerationData
CA::getRequestDefaults(Type type)
{
	initConfigFile();
	RequestGenerationData rgd = RequestGenerationData(m_impl->config, type);

	return rgd;
}


CRLGenerationData
CA::getCRLDefaults()
{
	initConfigFile();
	CRLGenerationData  crlgd = CRLGenerationData(m_impl->config, E_CRL);
	return crlgd;
}

void
CA::setIssueDefaults(Type type,
                     const CertificateIssueData& defaults)
{
	initConfigFile();
	defaults.commit2Config(*this, type);
	commitConfig2Template();
}

void
CA::setRequestDefaults(Type type,
                       const RequestGenerationData& defaults)
{
	initConfigFile();
	defaults.commit2Config(*this, type);
	commitConfig2Template();
}

void
CA::setCRLDefaults(const CRLGenerationData& defaults)
{
	initConfigFile();
	defaults.commit2Config(*this, E_CRL);
	commitConfig2Template();
}

std::vector<std::map<std::string, std::string> >
CA::getCertificateList()
{
	updateDB();

	std::vector< std::map<std::string, std::string> > ret;

	ret = OpenSSLUtils::listCertificates(m_impl->caName, m_impl->repositoryDir);

	return ret;
}

std::vector<std::map<std::string, std::string> >
CA::getRequestList()
{
	std::vector< std::map<std::string, std::string> > ret;

	ret = OpenSSLUtils::listRequests(m_impl->caName, m_impl->repositoryDir);

	return ret;
}


CertificateData
CA::getCA()
{
	return CertificateData_Priv(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem");
}


RequestData
CA::getRequest(const std::string& requestName)
{
	return RequestData_Priv(m_impl->repositoryDir + "/" + m_impl->caName + "/req/" + requestName + ".req");
}

CertificateData
CA::getCertificate(const std::string& certificateName)
{
	return CertificateData_Priv(m_impl->repositoryDir + "/" + m_impl->caName +
	                            "/newcerts/" + certificateName + ".pem");
}

CRLData
CA::getCRL()
{
	return CRLData_Priv(m_impl->repositoryDir + "/" + m_impl->caName + "/crl/crl.pem");
}

/**
 * Return the CA certificate in PEM or DER format
 *
 */
ByteBuffer
CA::exportCACert(FormatType exportType)
{
	ByteBuffer ret;

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem");

	if( exportType == E_DER )
	{
		ret = OpenSSLUtils::x509Convert(ret, E_PEM, E_DER);
	}

	return ret;
}



/**
 * Return the CA private key in PEM format.
 * If a new Password is given, the key will be encrypted
 * using the newPassword.
 * If newPassword is empty the returned key is decrypted.
 */
ByteBuffer
CA::exportCAKeyAsPEM(const std::string& newPassword)
{
	ByteBuffer ret;

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key");

	ret = OpenSSLUtils::rsaConvert(ret, E_PEM, E_PEM, m_impl->caPasswd, newPassword);

	return ret;
}

/**
 * Return the CA private key in DER format.
 * The private Key is decrypted.
 */
ByteBuffer
CA::exportCAKeyAsDER()
{
	ByteBuffer ret;

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key");

	ret = OpenSSLUtils::rsaConvert(ret, E_PEM, E_DER, m_impl->caPasswd, "");

	return ret;
}

/**
 * Return the CA certificate in PKCS12 format.
 * If withChain is true, all issuer certificates
 * will be included.
 */
ByteBuffer
CA::exportCAasPKCS12(const std::string& p12Password,
                     bool withChain)
{
	ByteBuffer ret;

	ret = OpenSSLUtils::createPKCS12
		(LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/" + "cacert.pem"),
		 LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/" + "cacert.key"),
		 m_impl->caPasswd,
		 p12Password,
		 ByteBuffer(),
		 m_impl->repositoryDir + "/.cas/",
		 withChain);

	return ret;
}

/**
 * Return the certificate in PEM or DER format
 *
 */
ByteBuffer
CA::exportCertificate(const std::string& certificateName,
                      FormatType exportType)
{
	ByteBuffer ret;

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" +
	                                certificateName + ".pem");

	if( exportType == E_DER )
	{
		ret = OpenSSLUtils::x509Convert(ret, E_PEM, E_DER);
	}

	return ret;
}

/**
 * Return the certificate private key in PEM format.
 * If a new Password is given, the key will be encrypted
 * using the newPassword.
 * If newPassword is empty the returned key is decrypted.
 */
ByteBuffer
CA::exportCertificateKeyAsPEM(const std::string& certificateName,
                              const std::string& keyPassword,
                              const std::string& newPassword)
{
	ByteBuffer ret;

	PerlRegEx rReq("^[[:xdigit:]]+:([[:xdigit:]]+[\\d-]*)$");
	std::vector<std::string> sa = rReq.capture(certificateName);

	if(sa.size() != 2)
	{
		LOGIT_ERROR("Cannot parse certificate Name");
		BLOCXX_THROW(ca_mgm::ValueException, __("Cannot parse the certificate name."));
	}

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" +
	                                sa[1] + ".key");

	ret = OpenSSLUtils::rsaConvert(ret, E_PEM, E_PEM, keyPassword, newPassword);

	return ret;
}

/**
 * Return the certificate private key in DER format.
 * The private Key is decrypted.
 */
ByteBuffer
CA::exportCertificateKeyAsDER(const std::string& certificateName,
                              const std::string& keyPassword)
{
	ByteBuffer ret;

	PerlRegEx rReq("^[[:xdigit:]]+:([[:xdigit:]]+[\\d-]*)$");
	std::vector<std::string> sa = rReq.capture(certificateName);

	if(sa.size() != 2)
	{
		LOGIT_ERROR("Cannot parse certificate Name");
		BLOCXX_THROW(ca_mgm::ValueException, __("Cannot parse the certificate name."));
	}

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" +
	                                sa[1] + ".key");

	ret = OpenSSLUtils::rsaConvert(ret, E_PEM, E_DER, keyPassword, "");

	return ret;
}

/**
 * Return the certificate in PKCS12 format.
 * If withChain is true, all issuer certificates
 * will be included.
 */
ByteBuffer
CA::exportCertificateAsPKCS12(const std::string& certificateName,
                              const std::string& keyPassword,
                              const std::string& p12Password,
                              bool withChain)
{
	ByteBuffer ret;

	PerlRegEx rReq("^[[:xdigit:]]+:([[:xdigit:]]+[\\d-]*)$");
	std::vector<std::string> sa = rReq.capture(certificateName);

	if(sa.size() != 2)
	{
		LOGIT_ERROR("Cannot parse certificate Name");
		BLOCXX_THROW(ca_mgm::ValueException, __("Cannot parse the certificate name."));
	}

	ByteBuffer caCert;
	if(!withChain)
	{
		caCert = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem");
	}

	ret = OpenSSLUtils::createPKCS12
		(LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" + certificateName +".pem"),
		 LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" + sa[1] + ".key"),
		 keyPassword,
		 p12Password,
		 caCert,
		 m_impl->repositoryDir + "/.cas/",
		 withChain);

	return ret;
}

/**
 * Export a CRL in the requested format type.
 *
 * @param the format type
 *
 * @return the CRL in the requested format
 */
ByteBuffer
CA::exportCRL(FormatType exportType)
{
	ByteBuffer ret;

	ret = LocalManagement::readFile(m_impl->repositoryDir + "/" + m_impl->caName + "/crl/crl.pem");

	if( exportType == E_DER )
	{
		ret = OpenSSLUtils::crlConvert(ret, E_PEM, E_DER);
	}

	return ret;
}


void
CA::deleteRequest(const std::string& requestName)
{
	path::PathInfo reqFile(m_impl->repositoryDir + "/" + m_impl->caName + "/req/" + requestName + ".req");
	if(!reqFile.exists())
	{
		LOGIT_ERROR("Request '" << reqFile.toString() <<"' does not exist." );
		BLOCXX_THROW(ca_mgm::SystemException, str::form(__("Request %s does not exist."),
		                                            reqFile.toString().c_str()).c_str());
	}

	OpenSSLUtils::delCAM(m_impl->caName, requestName, m_impl->repositoryDir);

	path::PathInfo keyFile(m_impl->repositoryDir + "/" + m_impl->caName + "/keys/" + requestName + ".key");

	int r = 0;

	if(keyFile.exists())
	{
		r = path::removeFile(keyFile.toString());
		// if removeFile failed an error was logged by removeFile
		// we continue and try to remove the request file
	}

	r = path::removeFile(reqFile.toString());
	if(r != 0)
	{
		BLOCXX_THROW(ca_mgm::SystemException,
		             // %1 is the error code
		             str::form(__("Removing the request failed (%1)."), r).c_str());
	}
}

void
CA::deleteCertificate(const std::string& certificateName,
                      bool requestToo)
{
	path::PathInfo certFile(m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" + certificateName + ".pem");
	if(!certFile.exists())
	{
		LOGIT_ERROR("Certificate does not exist." << certFile.toString());
		BLOCXX_THROW(ca_mgm::ValueException,
		             // %s is the absolute path to the certificate
		             str::form(__("Certificate %s does not exist."),
		                    certFile.toString().c_str()).c_str());
	}

	PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
	std::vector<std::string> sa = p.capture(certificateName);

	if(sa.size() != 3)
	{
		LOGIT_ERROR("Can not parse certificate name: " << certificateName);
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             // %s is the certificate name
		             str::form(__("Cannot parse the certificate name %s."), certificateName.c_str()).c_str());
	}

	std::string serial  = sa[1];
	std::string request = sa[2];

	std::string configFilename = initConfigFile();

	OpenSSLUtils ost(configFilename);

	std::string state = ost.status(serial);

	if(0 == str::compareCI(state, "Revoked") ||
	   0 == str::compareCI(state, "Expired"))
	{
		if(requestToo)
		{
			try
			{
				deleteRequest(request);
			}
			catch(ca_mgm::SystemException &e)
			{
				std::string msg = e.what();
				if(!PerlRegEx("does\\s+not\\s+exist").match(msg))
				{
					throw;
				}
				// else if the request file does not exist everything is ok
			}
		}

		int r = path::removeFile(certFile.toString());
		if(r != 0)
		{
			BLOCXX_THROW(ca_mgm::SystemException,
			             // %2 is the error code of rm
			             str::form(__("Removing the certificate failed: %d."), r).c_str());
		}
	}
	else
	{
		LOGIT_ERROR("Only revoked or expired certificates can be deleted. " <<
		            str::form("The status of the certificate is '%s'.", state.c_str()).c_str());
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             str::form(__("Only revoked or expired certificates can be deleted. The status of the certificate is %s."), state.c_str()).c_str());
	}
}

void
CA::updateDB()
{
	path::PathInfo db(m_impl->repositoryDir + "/" + m_impl->caName + "/index.txt");

	if(!db.exists())
	{
		LOGIT_ERROR("Database not found.");
		BLOCXX_THROW(ca_mgm::RuntimeException, __("Database not found."));
	}

	if(db.size() != 0)
	{
		std::string configFilename = initConfigFile();

		OpenSSLUtils ost(configFilename);

		ost.updateDB(m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.pem",
		             m_impl->repositoryDir + "/" + m_impl->caName + "/cacert.key",
		             m_impl->caPasswd);

	}
	// else => empty index.txt no database to update
}

bool
CA::verifyCertificate(const std::string& certificateName,
                      bool crlCheck,
                      const std::string& purpose)
{
	path::PathInfo certFile(m_impl->repositoryDir + "/" + m_impl->caName + "/newcerts/" + certificateName + ".pem");
	if(!certFile.exists())
	{
		LOGIT_ERROR("Certificate does not exist");
		BLOCXX_THROW(ca_mgm::SystemException, __("Certificate does not exist."));
	}

	if(purpose != "sslclient"    &&
	   purpose != "sslserver"    &&
	   purpose != "nssslserver"  &&
	   purpose != "smimesign"    &&
	   purpose != "smimeencrypt" &&
	   purpose != "crlsign"      &&
	   purpose != "any"          &&
	   purpose != "ocsphelper")
	{
		LOGIT_ERROR("Invalid purpose: " << purpose);
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid purpose %s."), purpose.c_str()).c_str());
	}

	std::string configFilename = initConfigFile();

	OpenSSLUtils ost(configFilename);

	std::string ret = ost.verify(certFile.toString(),
	                        m_impl->repositoryDir + "/.cas/",
	                        crlCheck,
	                        purpose);

	if(!ret.empty())
	{
		LOGIT_ERROR(ret);
		BLOCXX_THROW(ca_mgm::RuntimeException, ret.c_str());
	}

	return true;
}

CAConfig*
CA::getConfig()
{
	return m_impl->config;
}


/* ##########################################################################
 * ###          static Functions                                          ###
 * ##########################################################################
 */

void
CA::createRootCA(const std::string& caName,
                 const std::string& caPasswd,
                 const RequestGenerationData& caRequestData,
                 const CertificateIssueData& caIssueData,
                 const std::string& repos)
{
	if(!caRequestData.valid())
	{
		LOGIT_ERROR("Invalid CA request data");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid CA request data."));
	}

	if(!caIssueData.valid())
	{
		LOGIT_ERROR("Invalid CA issue data");
		BLOCXX_THROW(ca_mgm::ValueException, __("Invalid CA issue data."));
	}


	// Create the infrastructure

	try
	{
		OpenSSLUtils::createCaInfrastructure(caName, repos);
	}
	catch(blocxx::Exception &e)
	{
		LOGIT_ERROR(e);
		BLOCXX_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Error while creating the CA infrastructure."),
		                   e);
	}

	{
		OpenSSLUtils ost(repos + "/openssl.cnf.tmpl");

		// create key

		ost.createRSAKey(repos + "/" + caName + "/" + "cacert.key",
		                 caPasswd, caRequestData.getKeysize());
	}

	// Create CA Object
	CA tmpCA = CA(caName, caPasswd, repos);

	// copy template to config
	std::string configFilename = tmpCA.initConfigFile();

	tmpCA.removeDefaultsFromConfig();

	// write request data to config
	caRequestData.commit2Config(tmpCA, E_CA_Req);

	// copy Section, because "req" is hard coded in openssl :-(
	tmpCA.getConfig()->copySection(type2Section(E_CA_Req, false), "req");

	OpenSSLUtils ost(configFilename);

	// create request
	ost.createRequest(caRequestData.getSubjectDN(),
	                  repos + "/" + caName + "/" + "cacert.req",
	                  repos + "/" + caName + "/" + "cacert.key",
	                  caPasswd,
	                  "v3_req_ca",
	                  E_PEM,
	                  caRequestData.getChallengePassword(),
	                  caRequestData.getUnstructuredName());

	// write certificate issue data to config
	caIssueData.commit2Config(tmpCA, E_CA_Cert);

	// create the CA certificate

	ost.createSelfSignedCertificate(repos + "/" + caName + "/" + "cacert.pem",
	                                repos + "/" + caName + "/" + "cacert.key",
	                                repos + "/" + caName + "/" + "cacert.req",
	                                caPasswd, "v3_ca",
	                                (caIssueData.getEndDate() - caIssueData.getStartDate()) /(60*60*24));

	// some clean-ups

	int r = path::copyFile(repos + "/" + caName + "/" + "cacert.pem",
	                       repos + "/" + ".cas/" + caName + ".pem");

	if(r != 0)
	{
		LOGIT_INFO("Copy of cacert.pem to .cas/ failed: " << r);
	}

	rehashCAs(repos + "/.cas/");

	// reinit the config , write the defaults and copy back to template
	tmpCA.initConfigFile();
	DNObject_Priv dnp( caRequestData.getSubjectDN() );
	dnp.setDefaults2Config(tmpCA);
	tmpCA.commitConfig2Template();
}


void
CA::importCA(const std::string& caName,
             const ByteBuffer& caCertificate,
             const ByteBuffer& caKey,
             const std::string& caPasswd,
             const std::string& repos)
{
	if(caName.empty())
	{
		LOGIT_ERROR("CA name is empty");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("CA name is empty."));
	}

	path::PathInfo caDir(repos + "/" + caName);

	if(caDir.exists())
	{
		LOGIT_ERROR("CA directory already exists");
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("CA directory already exists."));
	}

	CertificateData cad = CertificateData_Priv(caCertificate, E_PEM);

	BasicConstraintsExt bs = cad.getExtensions().getBasicConstraints();

	if(!bs.isPresent() || !bs.isCA())
	{
		LOGIT_ERROR("According to 'basicConstraints', this is not a CA.");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("According to basicConstraints, this is not a CA."));
	}

	if(caKey.empty())
	{
		LOGIT_ERROR("CA key is empty");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("CA key is empty."));
	}

	PerlRegEx keyregex("-----BEGIN[\\w\\s]+KEY[-]{5}[\\S\\s\n]+-----END[\\w\\s]+KEY[-]{5}");

	if(!keyregex.match(std::string(caKey.data(), caKey.size())))
	{
		LOGIT_ERROR("Invalid Key data.");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid key data."));
	}

	if(caPasswd.empty())
	{
		LOGIT_ERROR("CA password is empty.");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("CA password is empty."));
	}

	PerlRegEx keycrypt("ENCRYPTED");
	if(keycrypt.match( std::string(caKey.data(), caKey.size()) ))
	{
		// Try to decrypt the key.
		// In case of invalid password rsaConvert throws an exception.
		ByteBuffer buf = OpenSSLUtils::rsaConvert(caKey, E_PEM, E_PEM, caPasswd, "");
	}

	try
	{
		OpenSSLUtils::createCaInfrastructure(caName, repos);
	}
	catch(blocxx::Exception &e)
	{
		LOGIT_ERROR(e);
		BLOCXX_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Error while creating the CA infrastructure."),
		                   e);
	}

	LocalManagement::writeFile(caCertificate, caDir.toString() + "/cacert.pem");

	if(keycrypt.match( std::string(caKey.data(), caKey.size()) ))
	{
		LocalManagement::writeFile(caKey,
		                           caDir.toString() + "/cacert.key");
	}
	else
	{
		ByteBuffer buf;

		try
		{
			buf = OpenSSLUtils::rsaConvert(caKey, E_PEM, E_PEM, "", caPasswd);
		}
		catch(Exception &e)
		{
			path::removeDirRecursive(repos + "/" + caName);

			LOGIT_ERROR ("Error during key encryption." );
			BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
			                   __("Error during key encryption."), e);
		}

		LocalManagement::writeFile(buf,
		                           caDir.toString() + "/cacert.key");
	}

	try
	{
	// write DN defaults
		CA tmpCA = CA(caName, caPasswd, repos);
		tmpCA.initConfigFile();
		DNObject_Priv dnp( cad.getSubjectDN() );
		dnp.setDefaults2Config(tmpCA);
		tmpCA.commitConfig2Template();
	}
	catch(Exception &e)
	{
		path::removeDirRecursive(repos + "/" + caName);

		LOGIT_ERROR ("Error during write defaults." );
		BLOCXX_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Error during write defaults."), e);
	}

	int r = path::copyFile(repos + "/" + caName + "/" + "cacert.pem",
	                       repos + "/" + ".cas/" + caName + ".pem");

	if(r != 0)
	{
		LOGIT_INFO("Copy of cacert.pem to .cas/ failed: " << r);
	}

	rehashCAs(repos + "/.cas/");
}


std::vector<std::string>
CA::getCAList(const std::string& repos)
{
	std::vector<std::string> caList;

	caList = OpenSSLUtils::listCA(repos);

	return caList;
}


std::list<std::vector<std::string> >
CA::getCATree(const std::string& repos)
{
	std::list<std::vector<std::string> > ret;

	std::vector<std::string> caList = CA::getCAList(repos);

	if(caList.empty())
	{
		return ret;
	}

	std::map<std::string, std::vector<std::string> > caHash;

	std::vector<std::string>::const_iterator it = caList.begin();
	for(; it != caList.end(); ++it)
	{
		CertificateData caData =
			LocalManagement::getCertificate(repos + "/" + (*it) + "/cacert.pem",
			                                E_PEM);

		std::vector<std::string> d;
		d.push_back(caData.getSubjectDN().getOpenSSLString());
		d.push_back(caData.getIssuerDN().getOpenSSLString());
		caHash[*it] = d;
	}


	std::map<std::string, std::vector<std::string> >::const_iterator chit = caHash.begin();
	for(; chit != caHash.end(); ++chit)
	{
		//       subject        ==       issuer
		if( ((*chit).second)[0] == ((*chit).second)[1] )
		{
			// root CA
			std::vector<std::string> d;
			d.push_back((*chit).first);
			d.push_back("");

			ret.push_back(d);   // push_front() ?
		}
		else
		{
			bool issuerFound = false;

			// sub CA; find caName of the issuer
			std::map<std::string, std::vector<std::string> >::const_iterator chitnew = caHash.begin();
			for(; chitnew != caHash.end(); ++chitnew)
			{
				//       issuer          ==       subject
				if(  ((*chit).second)[1] == ((*chitnew).second)[0]  )
				{
					std::vector<std::string> d;
					d.push_back((*chit).first);
					d.push_back((*chitnew).first);

					ret.push_back(d);
					issuerFound = true;
					break;
				}
			}

			if(!issuerFound)
			{
				// the issuer is not in our repository
				std::vector<std::string> d;
				d.push_back((*chit).first);
				d.push_back("");

				ret.push_back(d);
			}
		}
	}

	ret.sort(CATreeCompare());

	return ret;
}

CertificateIssueData
CA::getRootCAIssueDefaults(const std::string& repos)
{
	CAConfig *config = new CAConfig(repos+"/openssl.cnf.tmpl");
	CertificateIssueData cid = CertificateIssueData(config, E_CA_Cert);
	delete config;

	return cid;
}

RequestGenerationData
CA::getRootCARequestDefaults(const std::string& repos)
{
	CAConfig *config = new CAConfig(repos+"/openssl.cnf.tmpl");
	RequestGenerationData rgd = RequestGenerationData(config, E_CA_Req);
	delete config;

	return rgd;
}

void
CA::deleteCA(const std::string& caName,
             const std::string& caPasswd,
             bool force,
             const std::string& repos)
{
	if(caName.empty())
	{
		LOGIT_ERROR("Empty CA name.");
		BLOCXX_THROW(ca_mgm::ValueException, __("Empty CA name."));
	}

	path::PathInfo pi(repos + "/" + caName);

	if(!pi.exists())
	{
		LOGIT_ERROR("CA name does not exist.(" << pi.toString() << ")");
		BLOCXX_THROW_ERR(ca_mgm::ValueException,
		                 // %s is the absolute path name to the CA
		                 str::form(__("CA name does not exist (%s)."), pi.toString().c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	OpenSSLUtils ost(repos + "/" + caName + "/openssl.cnf.tmpl");

	bool ret = ost.checkKey(caName, caPasswd, "cacert", repos);

	if(!ret)
	{
		LOGIT_ERROR("Invalid CA password");
		BLOCXX_THROW_ERR(ca_mgm::ValueException, __("Invalid CA password."), E_INVALID_PASSWD);
	}

	if(!force)
	{
		path::PathInfo piIndex(repos + "/" + caName + "/index.txt");

		if(piIndex.exists() && piIndex.size() > 0)
		{
			// test if expire date of the CA is greater then "now"

			CertificateData ca =
				LocalManagement::getCertificate(repos + "/" + caName + "/cacert.pem",
				                                E_PEM);

			if( ca.getEndDate() > Date::now() )
			{
				LOGIT_ERROR("Deleting the CA is not allowed. " <<
				            "The CA must be expired or no certificate was signed with this CA");
				BLOCXX_THROW(ca_mgm::RuntimeException,
				             __("Deleting the CA is not allowed. The CA must be expired or never have signed a certificate."));
			}
			else
			{
				LOGIT_DEBUG("CA is expired");
			}
		}
		else
		{
			LOGIT_DEBUG("No index file or index file is empty");
		}
	}
	else
	{
		LOGIT_DEBUG("Force delete");
	}

	// ok, delete the CA

	int r = path::removeDirRecursive(repos + "/" + caName);
	if( r != 0 )
	{
		LOGIT_ERROR("Deleting the CA failed: " << r);
		BLOCXX_THROW(ca_mgm::SystemException,
		             // %1 is the error code of rm
		             str::form(__("Deleting the CA failed: %1."), r).c_str());
	}

	path::PathInfo p(repos + "/.cas/" + caName + ".pem");

	if(p.exists())
	{
		path::removeFile(p.toString());
	}

	p.stat(repos + "/.cas/crl_" + caName + ".pem");

	if(p.exists())
	{
		path::removeFile(p.toString());
	}

	rehashCAs(repos + "/.cas/");
}


//  private
CA::CA()
{}

CA::CA(const CA&)
{}

CA&
CA::operator=(const CA&)
{
	return *this;
}


void
CA::checkDNPolicy(const DNObject& dn, Type type)
{
	// These types are not supported by this method
	if(type == E_Client_Req || type == E_Server_Req ||
	   type == E_CA_Req     || type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException, str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = m_impl->config->exists(type2Section(type, false), "policy");
	if(!p)
	{
		LOGIT_ERROR("missing value 'policy' in config file");
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             __("The configuration file is missing a value for policy."));
	}
	std::string policySect = m_impl->config->getValue(type2Section(type, false), "policy");

	StringList policyKeys = m_impl->config->getKeylist(policySect);

	if(policyKeys.empty())
	{
		LOGIT_ERROR("Can not parse Section " << policySect);
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             str::form(__("Cannot parse section %s."), policySect.c_str()).c_str());
	}
	StringList::const_iterator it = policyKeys.begin();

	std::list<RDNObject> l = dn.getDN();

	bool policyFound = false;
	std::list<RDNObject> caDNList = getCA().getSubjectDN().getDN();

	for(; it != policyKeys.end(); ++it)
	{
		policyFound = false;  // reset

		// could be optional, supplied or match
		std::string policyString = m_impl->config->getValue(policySect, *it);

		LOGIT_DEBUG("PolicyKey:" << *it << "  PolicyString:"<< policyString);

		if(0 == str::compareCI(policyString, "optional"))
		{
			// do not care
			policyFound = true;
		}
		else if(0 == str::compareCI(policyString, "supplied"))
		{
			policyFound = true;

			// we need a value
			bool foundInDN = false;

			std::list<RDNObject>::const_iterator rdnit = l.begin();

			for(; rdnit != l.end(); ++rdnit)
			{
				if( 0 == str::compareCI(*it, (*rdnit).getType() ) )
				{
					foundInDN = true;

					if( (*rdnit).getValue().empty() )
					{
						int errorCode = E_GENERIC;
						if(*it == "countryName")
						{
							errorCode = E_C_EMPTY;
						}
						else if(*it == "stateOrProvinceName")
						{
							errorCode = E_ST_EMPTY;
						}
						else if(*it == "localityName")
						{
							errorCode = E_L_EMPTY;
						}
						else if(*it == "organizationName")
						{
							errorCode = E_O_EMPTY;
						}
						else if(*it == "organizationalUnitName")
						{
							errorCode = E_OU_EMPTY;
						}
						else if(*it == "commonName")
						{
							errorCode = E_CN_EMPTY;
						}
						else if(*it == "emailAddress")
						{
							errorCode = E_EM_EMPTY;
						}

						LOGIT_ERROR("Field '" << *it << "' must have a value");
						BLOCXX_THROW_ERR(ca_mgm::ValueException,
						                 str::form(__("Field %s must have a value."),
						                        (*it).c_str()).c_str(),
						                 errorCode);
					}
				}
			}
			if(!foundInDN)
			{
				int errorCode = E_GENERIC;
				if(*it == "countryName")
				{
					errorCode = E_C_NF;
				}
				else if(*it == "stateOrProvinceName")
				{
					errorCode = E_ST_NF;
				}
				else if(*it == "localityName")
				{
					errorCode = E_L_NF;
				}
				else if(*it == "organizationName")
				{
					errorCode = E_O_NF;
				}
				else if(*it == "organizationalUnitName")
				{
					errorCode = E_OU_NF;
				}
				else if(*it == "commonName")
				{
					errorCode = E_CN_NF;
				}
				else if(*it == "emailAddress")
				{
					errorCode = E_EM_NF;
				}
				LOGIT_ERROR("The '" << *it << "' field must be defined.");
				BLOCXX_THROW_ERR(ca_mgm::ValueException,
				                 str::form(__("%s must be defined."), (*it).c_str()).c_str(),
				                 errorCode);
			}
		}
		else if(0 == str::compareCI(policyString, "match"))
		{
			std::string caMatchValue;
			std::string reqMatchValue;

			// read the CA and check the value
			// *it == key (e.g. commonName, emailAddress, ...

			std::list<RDNObject>::const_iterator rdnit = l.begin();
			RDNObject rdn2check = RDNObject_Priv(*it, "");

			for(; rdnit != l.end(); ++rdnit)
			{
				if( 0 == str::compareCI(*it, (*rdnit).getType() ) )
				{
					rdn2check = *rdnit;
					break;
				}
			}

			bool validMatch = false;

			std::list<RDNObject>::const_iterator caRdnIT = caDNList.begin();
			for(; caRdnIT != caDNList.end(); ++caRdnIT)
			{

				LOGIT_DEBUG("Type (ca == request): " <<(*caRdnIT).getType() << "==" << rdn2check.getType());
				LOGIT_DEBUG("Value(ca == request): " <<(*caRdnIT).getValue() << "==" << rdn2check.getValue());

				if(0 == str::compareCI((*caRdnIT).getType(), rdn2check.getType() ))
				{
					if((*caRdnIT).getValue()  == rdn2check.getValue())
					{
						validMatch = true;
						break;
					}
					else
					{
						caMatchValue = (*caRdnIT).getValue();
						reqMatchValue = rdn2check.getValue();
					}
				}
			}

			if(!validMatch)
			{
				int errorCode = E_GENERIC;
				if(*it == "countryName")
				{
					errorCode = E_C_NM;
				}
				else if(*it == "stateOrProvinceName")
				{
					errorCode = E_ST_NM;
				}
				else if(*it == "localityName")
				{
					errorCode = E_L_NM;
				}
				else if(*it == "organizationName")
				{
					errorCode = E_O_NM;
				}
				else if(*it == "organizationalUnitName")
				{
					errorCode = E_OU_NM;
				}
				else if(*it == "commonName")
				{
					errorCode = E_CN_NM;
				}
				else if(*it == "emailAddress")
				{
					errorCode = E_EM_NM;
				}

				// policy does not match
				LOGIT_ERROR("The '"<<*it<<"' field needed to be the same in the CA certificate ("<<
				            caMatchValue<<") and the request ("<< reqMatchValue <<")");

				BLOCXX_THROW_ERR(ca_mgm::ValueException,
				                 str::form(__("%s must be the same in the CA certificate (%s) and the request (%s)."),
				                        (*it).c_str(), caMatchValue.c_str(), reqMatchValue.c_str()).c_str(),
				                 errorCode);
			}

			policyFound = true;

		}
		if(!policyFound)
		{
			LOGIT_ERROR("Invalid policy in config file ? (" << *it << "/" << policyString << ")");
			BLOCXX_THROW(ca_mgm::SyntaxException,
			             __("The configuration file seems to have an invalid policy."));
		}
	}
	return;
}

std::string
CA::initConfigFile()
{
	return m_impl->initConfigFile();
}

void
CA::commitConfig2Template()
{
	if(m_impl->config)
	{
		m_impl->templ = m_impl->config->clone(m_impl->repositoryDir +
		                                      "/" + m_impl->caName  +
		                                      "/openssl.cnf.tmpl");
		delete m_impl->config;
		m_impl->config = NULL;
	}
	else
	{
		LOGIT_ERROR("config not initialized");
		BLOCXX_THROW(ca_mgm::RuntimeException, __("The configuration is not initialized."));
	}
}

void
CA::removeDefaultsFromConfig()
{
	if(!m_impl->config)
	{
		LOGIT_ERROR("config not initialized");
		BLOCXX_THROW(ca_mgm::RuntimeException, __("The configuration is not initialized."));
	}

	bool p = m_impl->config->exists("req_ca", "distinguished_name");
	if(!p)
	{
		LOGIT_ERROR("missing section 'distinguished_name' in config file");
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             __("Missing section 'distinguished_name' in the configuration file."));
	}
	std::string dnSect = m_impl->config->getValue("req_ca", "distinguished_name");

	StringList dnKeys = m_impl->config->getKeylist(dnSect);

	if(dnKeys.empty())
	{
		LOGIT_ERROR("Can not parse Section " << dnSect);
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             str::form(__("Cannot parse section %s."), dnSect.c_str()).c_str());
	}
	StringList::const_iterator it = dnKeys.begin();

	for(; it != dnKeys.end(); ++it)
	{
		if(str::endsWithCI(*it, "_default"))
		{
			// delete the default value
			m_impl->config->deleteValue(dnSect, *it);
		}
	}
}

}
