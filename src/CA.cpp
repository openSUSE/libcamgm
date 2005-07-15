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
#include  <limal/Exception.hpp>
#include  <blocxx/Exec.hpp>
#include  <blocxx/EnvVars.hpp>

#include  "CertificateData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "CRLData_Priv.hpp"
#include  "CATools.h"
#include  "OPENSSL.h"

#include  "Utils.hpp"
#include  "Commands.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CA::CA(const String& caName, const String& caPasswd, const String& repos)
    : caName(caName), caPasswd(caPasswd), repositoryDir(repos),
      config(NULL),
      templ(new CAConfig(repositoryDir+"/"+caName+"/openssl.cnf.tmpl"))
{
}

CA::~CA()
{
    StringArray cmd;
    cmd.push_back(RM_COMMAND);
    cmd.push_back(repositoryDir+"/"+caName+"/openssl.cnf");
    try {
        blocxx::Exec::safeSystem(cmd, blocxx::EnvVars());
    } catch(Exception &e) {
        // ignore errors
        LOGIT_INFO("Remove of openssl.cnf failed. " << e);
    }
}
        
bool
CA::createSubCA(const String& keyPasswd,
                const RequestGenerationData& caRequestData,
                const CertificateIssueData& ca)
{
    return false;
}


blocxx::String
CA::createRequest(const String& keyPasswd,
                  const RequestGenerationData& requestData)
{
    return String();
}


blocxx::String
CA::issueCertificate(const String& requestName,
                     const CertificateIssueData& issueData)
{
    return String();
}

blocxx::String
CA::createCertificate(const String& keyPasswd,
                      const RequestGenerationData& requestData,
                      const CertificateIssueData&  certificateData)
{
    return String();
}

bool
CA::revokeCertificate(const String& certificateName,
                      const CRLReason& crlReason)
{
    return false;
}


bool
CA::createCRL(const CRLGenerationData& crlData)
{
    return false;
}


blocxx::String
CA::importRequest(const ByteArray& request,
                  FormatType formatType)
{
    return String();
}

CertificateIssueData
CA::getIssueDefaults(Type type)
{
    initConfigFile();
    CertificateIssueData cid = CertificateIssueData(*this, type);
    return cid;
}

RequestGenerationData
CA::getRequestDefaults(Type type)
{
    initConfigFile();
    RequestGenerationData rgd = RequestGenerationData(*this, type);

    return rgd;
}


CRLGenerationData
CA::getCRLDefaults()
{
    initConfigFile();
    CRLGenerationData  crlgd = CRLGenerationData(*this, CRL);
    return crlgd;
}

bool
CA::setIssueDefaults(Type type,
                     const CertificateIssueData& defaults)
{
    initConfigFile();
    if(config) {
        defaults.commit2Config(*this, type);
        commitConfig2Template();
        return true;
    }
    return false;
}

bool
CA::setRequestDefaults(Type type,
                       const RequestGenerationData& defaults)
{
    initConfigFile();
    if(config) {
        defaults.commit2Config(*this, type);
        commitConfig2Template();
        return true;
    }
    return false;
}

bool
CA::setCRLDefaults(const CRLGenerationData& defaults)
{
    initConfigFile();
    if(config) {
        defaults.commit2Config(*this, CRL);
        commitConfig2Template();
        return true;
    }
    return false;
}

StringMapList
CA::getCertificateList()
{
    return StringMapList();
}

StringMapList
CA::getRequestList()
{
    return StringMapList();
}


CertificateData
CA::getCA()
{
    return CertificateData_Priv();
}


RequestData
CA::getRequest(const String& requestName)
{
    return RequestData_Priv();
}

CertificateData
CA::getCertificate(const String& certificateName)
{
    return CertificateData_Priv();
}

CRLData
CA::getCRL()
{
    return CRLData_Priv();
}

ByteArray
CA::exportCACert(FormatType exportType)
{
    return ByteArray();
}
        
ByteArray
CA::exportCAKey(bool encrypted)
{
    return ByteArray();
}
        
ByteArray
CA::exportCAasPKCS12(const String& p12Passwd,
                     bool withChain)
{
    return ByteArray();
}

ByteArray
CA::exportCertificate(const String& certificateName,
                      const String& keyPasswd,
                      FormatType exportType)
{
    return ByteArray();
}
        
ByteArray
CA::exportCertificateKey(const String& certificateName,
                         const String& keyPasswd,
                         bool encrypted)
{
    return ByteArray();
}
        
ByteArray
CA::exportCertificateasPKCS12(const String& certificateName,
                              const String& keyPasswd,
                              const String& p12Passwd,
                              bool withChain)
{
    return ByteArray();
}

ByteArray
CA::exportCRL(FormatType exportType)
{
    return ByteArray();
}


bool
CA::deleteCA(bool force)
{
    return false;
}

bool
CA::deleteRequest(const String& requestName)
{
    return false;
}

bool
CA::deleteCertificate(const String& certificateName)
{
    return false;
}

bool
CA::updateDB()
{
    return false;
}
        
bool
CA::verifyCertificate(const String& certificateName,
                      bool crlCheck,
                      CertificatePurpose purpose)
{
    return false;
}

void
CA::initConfigFile()
{
    if(templ) {
        config = templ->clone(repositoryDir+"/"+caName+"/openssl.cnf");
    } else {
        LOGIT_ERROR("template not initialized");
        BLOCXX_THROW(limal::RuntimeException, "template not initialized");
    }
}

void
CA::commitConfig2Template()
{
    if(config) {
        templ = config->clone(repositoryDir+"/"+caName+"/openssl.cnf.tmpl");
        delete config;
        config = NULL;
    } else {
        LOGIT_ERROR("config not initialized");
        BLOCXX_THROW(limal::RuntimeException, "config not initialized");
    }
}

CAConfig*
CA::getConfig()
{
    return config;
}

/* ##########################################################################
 * ###          static Functions                                          ###
 * ##########################################################################
 */

bool 
CA::createRootCA(const String& caName,
                 const String& caPasswd,
                 const RequestGenerationData& caRequestData,
                 const CertificateIssueData& caIssueData,
                 const String& repos)
{
    // Create the infrastructure

    try {
        createCaInfrastructure(caName, repos);
    } catch(blocxx::Exception &e) {
        LOGIT_ERROR(e);
        BLOCXX_THROW_SUBEX(limal::SystemException, 
                           "Error during create CA infrastructure",
                           e);
    }
    
    // Create CA Object
    CA tmpCA = CA(caName, caPasswd, repos);

    // copy template to config
    tmpCA.initConfigFile();
    
    // write request data to config
    caRequestData.commit2Config(tmpCA, CA_Req);

    blocxx::Map<blocxx::String,blocxx::String > hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = repos + "/" + caName + "/" + "openssl.cnf";;
    hash["DEBUG"] = "1";
    OPENSSL ossl(hash);

    // create key
    hash.clear();
    hash["OUTFILE"] = repos + "/" + caName + "/" + "cacert.key";
    hash["PASSWD"] = caPasswd;
    hash["BITS"] = String(caRequestData.getKeysize());
    //    hash[""] = "";
	blocxx::String k = ossl.createKey(hash);

    // create request
    hash.clear();
    hash["OUTFILE"] = repos + "/" + caName + "/" + "cacert.req";
    hash["KEYFILE"] = repos + "/" + caName + "/" + "cacert.key";
    hash["PASSWD"] = caPasswd;
    //hash[""] = "";

    blocxx::List<RDNObject> dn = caRequestData.getSubject().getDN();
    blocxx::List<RDNObject>::const_iterator it = dn.begin();
    blocxx::Array<blocxx::String> sdn;
    for(; it != dn.end(); ++it) {
        sdn.push_back( (*it).getValue() );
    }
    sdn.push_back(caRequestData.getChallengePassword());
    sdn.push_back(caRequestData.getUnstructuredName());

    k = ossl.createReq(&hash, &sdn);

    // write certificate issue data to config
    caIssueData.commit2Config(tmpCA, CA_Cert);

    // create the CA certificate
    hash.clear();
    hash["OUTFILE"] = repos + "/" + caName + "/" + "cacert.pem";
    hash["KEYFILE"] = repos + "/" + caName + "/" + "cacert.key";
    hash["REQFILE"] = repos + "/" + caName + "/" + "cacert.req";
    hash["PASSWD"]  = caPasswd;
    hash["DAYS"]    = String((caIssueData.getEndDate() - caIssueData.getStartDate()) /(60*60*24));

    k = ossl.createSelfSignedCert(hash);

    // some clean-ups 
    StringArray cmd;
    cmd.push_back(CP_COMMAND);
    cmd.push_back(repos + "/" + caName + "/" + "cacert.pem");
    cmd.push_back(repos + "/" + ".cas/" + caName + ".pem");
    blocxx::Exec::safeSystem(cmd, blocxx::EnvVars());
    
    cmd.clear();
    cmd.push_back(C_REHASH_COMMAND);
    cmd.push_back(repos + "/" + ".cas/");

    blocxx::EnvVars env;
    env.addVar("PATH", "/usr/bin/");
    blocxx::Exec::safeSystem(cmd, env);
    
    return true;
}
       

bool
CA::importCA(const String& caName,
             const String& caCertificate,
             const String& cakey,
             const String& caPasswd)
{
    return false;
}


StringList
CA::getCAList()
{
    return StringList();
}

        
blocxx::List<StringList>
CA::getCATree()
{
    return List<StringList>();
}


//  private
CA::CA()
{
}

CA::CA(const CA&)
{
}

CA&
CA::operator=(const CA&)
{
    return *this;
}


