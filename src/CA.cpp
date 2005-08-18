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
#include  <limal/PathUtils.hpp>
#include  <limal/PathInfo.hpp>
#include  <blocxx/Exec.hpp>
#include  <blocxx/EnvVars.hpp>
#include  <blocxx/MD5.hpp>
#include  <blocxx/DateTime.hpp>


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
    //FIXME: check if caName is not empty
    if(caName.empty()) {
        LOGIT_ERROR("Empty CA name.");
        BLOCXX_THROW(limal::ValueException, "Empty CA name.");
    }

}

CA::~CA()
{
    path::PathInfo pi(repositoryDir+"/"+caName+"/openssl.cnf");
    if(pi.exists()) {
        int r = path::removeFile(repositoryDir+"/"+caName+"/openssl.cnf");
        
        if(r != 0) {
            LOGIT_INFO("Remove of openssl.cnf failed: " << r);
        }
    }
}
        
bool
CA::createSubCA(const String& newCaName,
                const String& keyPasswd,
                const RequestGenerationData& caRequestData,
                const CertificateIssueData& caIssueData)
{

    String certificate = createCertificate(keyPasswd,
                                           caRequestData,
                                           caIssueData,
                                           CA_Cert);

    
    try {
        createCaInfrastructure(newCaName, repositoryDir);
    } catch(blocxx::Exception &e) {
        LOGIT_ERROR(e);
        BLOCXX_THROW_SUBEX(limal::SystemException, 
                           "Error during create CA infrastructure",
                           e);
    }
    String request;

    PerlRegEx p("^([[:xdigit:]]+):([[:xdigit:]]+[\\d-]*)$");
    StringArray sa = p.capture(certificate); 

    if(sa.size() == 3) {
        request = sa[2];
    } else {
        // cleanup
        path::removeDirRecursive(repositoryDir + "/" + newCaName);

        LOGIT_ERROR("Can not parse certificate name: " << certificate);
        BLOCXX_THROW(limal::RuntimeException, 
                     Format("Can not parse certificate name: ", certificate).c_str());
    }

    int r = path::copyFile(repositoryDir + "/" + caName + "/keys/" + request + ".key",
                           repositoryDir + "/" + newCaName + "/cacert.key");
    if(r != 0) {
        // cleanup
        path::removeDirRecursive(repositoryDir + "/" + newCaName);

        LOGIT_ERROR("Can not copy the private key." << r);
        BLOCXX_THROW(limal::SystemException, "Can not copy the private key.");
    }

    r = path::copyFile(repositoryDir + "/" + caName + "/newcerts/" + certificate + ".pem",
                       repositoryDir + "/" + newCaName + "/cacert.pem");
    if(r != 0) {
        // cleanup
        path::removeDirRecursive(repositoryDir + "/" + newCaName);

        LOGIT_ERROR("Can not copy the certificate." << r);
        BLOCXX_THROW(limal::SystemException, "Can not copy the certificate.");
    }

    r = path::copyFile(repositoryDir + "/" + newCaName + "/" + "cacert.pem",
                       repositoryDir + "/" + ".cas/" + newCaName + ".pem");
    
    if(r != 0) {
        LOGIT_INFO("Copy of cacert.pem to .cas/ failed: " << r);
    }
    
    StringArray cmd;
    cmd.push_back(C_REHASH_COMMAND);
    cmd.push_back(repositoryDir + "/" + ".cas/");

    blocxx::EnvVars env;
    env.addVar("PATH", "/usr/bin/");

    String stdOutput;
    String errOutput;
    int    status = 0;
    try {

        blocxx::Exec::executeProcessAndGatherOutput(cmd, stdOutput, errOutput, status, env);

    } catch(Exception& e) {
        LOGIT_INFO( "c_rehash exception:" << e);
        status = -1;
    }
    if(status != 0) {
        LOGIT_INFO( "c_rehash status:" << String(status));
    }
    if(!errOutput.empty()) {
        LOGIT_INFO("c_rehash stderr:" << errOutput);
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG("c_rehash stdout:" << stdOutput);
    }
    
    return true;
}


blocxx::String
CA::createRequest(const String& keyPasswd,
                  const RequestGenerationData& requestData,
                  Type requestType)
{
    if(!requestData.valid()) {
        LOGIT_ERROR("Invalid request data");
        BLOCXX_THROW(limal::ValueException, "Invalid request data");
    }
  

    blocxx::Map<blocxx::String,blocxx::String > hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = repositoryDir + "/" + caName + "/" + "openssl.cnf";;
    hash["DEBUG"] = "1";
    OPENSSL ossl(hash);

    String opensslDN = requestData.getSubject().getOpenSSLString();
    blocxx::MD5 md5(opensslDN);
    String request = md5.toString() + "-" +
        String(blocxx::DateTime::getCurrent().get());
           
    path::PathInfo dKey(repositoryDir + "/" + caName + "/keys/"+ request + ".key");
    if(dKey.exists()) {
        LOGIT_ERROR("Duplicate DN. Key '" << request <<".key' already exists.");
        BLOCXX_THROW(RuntimeException,
                     Format("Duplicate DN. Key '%1.key' already exists.", request).c_str());
    }

    path::PathInfo r(repositoryDir + "/" + caName + "/req/"+ request + ".req");
    if(r.exists()) {
        LOGIT_ERROR("Duplicate DN. Request '" << request <<".req' already exists.");
        BLOCXX_THROW(RuntimeException,
                     Format("Duplicate DN. Request '%1.req' already exists.", request).c_str());
    }

    // copy template to config
    initConfigFile();
    
    // write request data to config
    requestData.commit2Config(*this, requestType);

    // copy Section, because "req" is hard coded in openssl :-(
    config->copySection(type2Section(requestType, false), "req");

    // create key
    hash.clear();
    hash["OUTFILE"] = repositoryDir + "/" + caName + "/keys/"+ request + ".key";
    hash["PASSWD"]  = keyPasswd;
    hash["BITS"]    = String(requestData.getKeysize());
    //    hash[""] = "";
	blocxx::String k = ossl.createKey(hash);

    // create request
    hash.clear();
    hash["OUTFILE"]   = repositoryDir + "/" + caName + "/req/"+ request + ".req";
    hash["KEYFILE"]   = repositoryDir + "/" + caName + "/keys/"+ request + ".key";
    hash["PASSWD"]    = keyPasswd;
    hash["EXTENSION"] = type2Section(requestType, true);
    //hash[""] = "";

    blocxx::List<RDNObject> dn = requestData.getSubject().getDN();
    blocxx::List<RDNObject>::const_iterator it = dn.begin();
    blocxx::Array<blocxx::String> sdn;
    for(; it != dn.end(); ++it) {
        sdn.push_back( (*it).getValue() );
    }
    sdn.push_back(requestData.getChallengePassword());
    sdn.push_back(requestData.getUnstructuredName());

    k = ossl.createReq(&hash, &sdn);

    hash.clear();
    hash["MD5"] = request;
    hash["DN"]  = opensslDN;
    hash["REPOSITORY"]  = repositoryDir;
    
    addCAM(caName, &hash);

    return request;
}


blocxx::String
CA::issueCertificate(const String& requestName,
                     const CertificateIssueData& issueData,
                     Type certType)
{
    String requestFile = String(repositoryDir + "/" + caName + "/req/"+ requestName + ".req");
    path::PathInfo p(requestFile);
    if(!p.exists()) {
        LOGIT_ERROR("Request does not exist.(" << requestFile << ")");
        BLOCXX_THROW(ValueException, 
                     Format("Request does not exist.(%1)", requestFile ).c_str());
    }

    if(!issueData.valid()) {
        LOGIT_ERROR("Invalid issue data");
        BLOCXX_THROW(limal::ValueException, "Invalid issue data");
    }
    
    String serial      = nextSerial(caName, repositoryDir);
    String certificate = serial + ":" + requestName;

    // FIXME:
    // parse the CA and check if the end date of the ca is greater
    // than the end date of the certificate


    // FIXME:
    // Check the DN Policy

    // copy template to config
    initConfigFile();
    
    // write data to config
    issueData.commit2Config(*this, certType);

    blocxx::Map<blocxx::String,blocxx::String > hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = repositoryDir + "/" + caName + "/" + "openssl.cnf";;
    hash["DEBUG"]  = "1";
    OPENSSL ossl(hash);

    hash.clear();
    hash["REQFILE"]    = repositoryDir + "/" + caName + "/req/"+ requestName + ".req";
    hash["CAKEY"]      = repositoryDir + "/" + caName + "/cacert.key";
    hash["CACERT"]     = repositoryDir + "/" + caName + "/cacert.pem";
    hash["START_DATE"] = String(issueData.getStartDateAsString());
    hash["END_DATE"]   = String(issueData.getEndDateAsString());
    hash["PASSWD"]     = caPasswd;
    hash["CA_SECTION"] = type2Section(certType, false);
    hash["EXTS"]       = type2Section(certType, true);
    hash["OUTDIR"]     = repositoryDir + "/" + caName + "/certs/";
    hash["OUTFILE"]    = repositoryDir + "/" + caName + "/newcerts/" + certificate + ".pem";
    hash["NOTEXT"]     = "1";

	blocxx::String c = ossl.issueReq(hash);

    return certificate;
}

blocxx::String
CA::createCertificate(const String& keyPasswd,
                      const RequestGenerationData& requestData,
                      const CertificateIssueData&  certificateData,
                      Type type)
{
    Type t = Client_Req;

    if(type == Client_Req || type == Client_Cert) {
        t = Client_Req;
    }
    if(type == Server_Req || type == Server_Cert) {
        t = Server_Req;
    }
    if(type == CA_Req || type == CA_Cert) {
        t = CA_Req;
    }

    String requestName = createRequest(keyPasswd, requestData, t);

    if(type == Client_Req || type == Client_Cert) {
        t = Client_Cert;
    }
    if(type == Server_Req || type == Server_Cert) {
        t = Server_Cert;
    }
    if(type == CA_Req || type == CA_Cert) {
        t = CA_Cert;
    }

    String certificate;

    try {

        certificate = issueCertificate(requestName, certificateData, t);
        
    } catch(blocxx::Exception &e) {
        Map<String, String> hash;
        hash["MD5"] = requestName;
        hash["REPOSITORY"]  = repositoryDir;
        
        delCAM(caName, &hash);
        
        path::removeFile(repositoryDir + "/" + caName + "/keys/" + requestName + ".key");
        path::removeFile(repositoryDir + "/" + caName + "/req/" + requestName + ".req");
        BLOCXX_THROW_SUBEX(limal::RuntimeException, "issueCertificate() failed", e);
    }

    return certificate;
}

bool
CA::revokeCertificate(const String& certificateName,
                      const CRLReason& crlReason)
{
    path::PathInfo pi(repositoryDir + "/" + caName + "/newcerts/" + certificateName + ".pem");
    if(!pi.exists()) {
        LOGIT_ERROR("File '" << certificateName << ".pem' not found in repository");
        BLOCXX_THROW(limal::SystemException,
                     Format("File '%1' not found in repositoy", certificateName).c_str());
    }

    if(!crlReason.valid()) {
        LOGIT_ERROR("Invalid CRL reason");
        BLOCXX_THROW(limal::ValueException, "Invalid CRL reason");
    }

    Map<String, String> hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = repositoryDir + "/" + caName + "/" + "openssl.cnf";;
    hash["DEBUG"] = "1";
    OPENSSL ossl(hash);

    String reason = crlReason.getReasonAsString();

    hash.clear();
    hash["CAKEY"] = repositoryDir + "/" + caName + "/cacert.key";
    hash["CACERT"] = repositoryDir + "/" + caName + "/cacert.pem";;
    hash["PASSWD"] = caPasswd;
    hash["INFILE"] = repositoryDir + "/" + caName + "/newcerts/" + certificateName + ".pem";
    //hash[""] = "";
    
    if(reason == "certificateHold") {
        
        hash["CRL_REASON"] = reason;
        hash["CRL_REASON_EXTRA"] = crlReason.getHoldInstruction();
      
    } else if(reason == "keyCompromise") {

        hash["CRL_REASON"] = reason;
        hash["CRL_REASON_EXTRA"] = String(crlReason.getKeyCompromiseDateAsString());

    } else if(reason == "CACompromise") {

        hash["CRL_REASON"] = reason;
        hash["CRL_REASON_EXTRA"] = String(crlReason.getCACompromiseDateAsString());
  
    } else if(reason != "none") {
        
        hash["CRL_REASON"] = reason;
        
    }

    ossl.revokeCert(hash);

    return true;
}


bool
CA::createCRL(const CRLGenerationData& crlData)
{
    if(!crlData.valid()) {
        LOGIT_ERROR("Invalid CRL data");
        BLOCXX_THROW(limal::ValueException, "Invalid CRL data");
    }

    // copy template to config
    initConfigFile();
    
    // write crl data to config
    crlData.commit2Config(*this, CRL);

    Map<String, String> hash;
    hash["BINARY"] = OPENSSL_COMMAND;
    hash["CONFIG"] = repositoryDir + "/" + caName + "/" + "openssl.cnf";;
    hash["DEBUG"] = "1";
    OPENSSL ossl(hash);

    hash.clear();
    hash["CAKEY"]   = repositoryDir + "/" + caName + "/cacert.key";
    hash["CACERT"]  = repositoryDir + "/" + caName + "/cacert.pem";;
    hash["PASSWD"]  = caPasswd;
    hash["HOURS"]   = String(crlData.getCRLLifeTime());
    hash["OUTFORM"] = "PEM";
    hash["OUTFILE"] = repositoryDir + "/" + caName + "/crl/crl.pem";
    hash["EXTENSION"] = "v3_crl";
    //hash[""] = "";

    ossl.issueCRL(hash);
    
    int r = path::copyFile(repositoryDir + "/" + caName + "/crl/crl.pem",
                           repositoryDir + "/" + ".cas/crl_" + caName + ".pem");
    
    if(r != 0) {
        LOGIT_INFO("Copy of crl.pem to .cas/ failed: " << r);
    }
    
    StringArray cmd;
    cmd.push_back(C_REHASH_COMMAND);
    cmd.push_back(repositoryDir + "/" + ".cas/");

    blocxx::EnvVars env;
    env.addVar("PATH", "/usr/bin/");

    String stdOutput;
    String errOutput;
    int    status = 0;
    try {

        blocxx::Exec::executeProcessAndGatherOutput(cmd, stdOutput, errOutput, status, env);

    } catch(Exception& e) {
        LOGIT_INFO( "c_rehash exception:" << e);
        status = -1;
    }
    if(status != 0) {
        LOGIT_INFO( "c_rehash status:" << String(status));
    }
    if(!errOutput.empty()) {
        LOGIT_INFO("c_rehash stderr:" << errOutput);
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG("c_rehash stdout:" << stdOutput);
    }

    return true;
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
    CertificateIssueData cid = CertificateIssueData(config, type);
    return cid;
}

RequestGenerationData
CA::getRequestDefaults(Type type)
{
    initConfigFile();
    RequestGenerationData rgd = RequestGenerationData(config, type);

    return rgd;
}


CRLGenerationData
CA::getCRLDefaults()
{
    initConfigFile();
    CRLGenerationData  crlgd = CRLGenerationData(config, CRL);
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

blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
CA::getCertificateList()
{
    updateDB();

    Array<Map<String, String> > ret;

    ret = listCertificates(caName, repositoryDir);

    return ret;
}

blocxx::Array<blocxx::Map<blocxx::String, blocxx::String> >
CA::getRequestList()
{
    Array<Map<String, String> > ret;

    ret = listRequests(caName, repositoryDir);

    return ret;
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
    path::PathInfo reqFile(repositoryDir + "/" + caName + "/req/" + requestName + ".req");
    if(!reqFile.exists()) {
        LOGIT_ERROR("Request '" << reqFile.toString() <<"' does not exist." );
        BLOCXX_THROW(limal::SystemException, Format("Request '%1' does not exist.",
                                                    reqFile.toString()).c_str());
    }
    
  
    Map<String, String> hash;
    hash["PASSWORD"]   = caPasswd;
    hash["CACERT"]     = "1";
    hash["REPOSITORY"] = repositoryDir;
    //hash[""] = "";
    
    bool passOK = checkKey(caName, &hash);
    
    if(!passOK) {
        LOGIT_ERROR("Invalid CA password");
        BLOCXX_THROW(limal::ValueException, "Invalid CA password");
    }

    hash.clear();
    hash["MD5"]        = requestName;
    hash["REPOSITORY"] = repositoryDir;
    //hash[""] = "";

    delCAM(caName, &hash);

    path::PathInfo keyFile(repositoryDir + "/" + caName + "/keys/" + requestName + ".key");
    
    int r = 0;

    if(keyFile.exists()) {
        r = path::removeFile(keyFile.toString());
        // if removeFile failed an error was logged by removeFile
        // we continue and try to remove the request file
    }

    r = path::removeFile(reqFile.toString());
    if(r != 0) {
        BLOCXX_THROW(limal::SystemException, 
                     Format("Removing the request failed: %1.", r).c_str());
    }    

    return true;
}

bool
CA::deleteCertificate(const String& certificateName)
{
    return false;
}

bool
CA::updateDB()
{
    bool ret = false;

    path::PathInfo db(repositoryDir + "/" + caName + "/index.txt");
    
    if(!db.exists()) {
        LOGIT_ERROR("Database not found.");
        BLOCXX_THROW(limal::RuntimeException, "Database not found.");
    }
    if(db.size() == 0) {
        // no certificate created => test only the caPasswd

        Map<String, String> hash;
        hash["PASSWORD"]   = caPasswd;
        hash["CACERT"]     = "1";
        hash["REPOSITORY"] = repositoryDir;
        //hash[""] = "";

        ret = checkKey(caName, &hash);

    } else {
        // test password first, for a better error message

        Map<String, String> hash;
        hash["PASSWORD"]   = caPasswd;
        hash["CACERT"]     = "1";
        hash["REPOSITORY"] = repositoryDir;
        //hash[""] = "";

        ret = checkKey(caName, &hash);
        
        initConfigFile();
        hash.clear();
        hash["BINARY"] = OPENSSL_COMMAND;
        hash["CONFIG"] = repositoryDir + "/" + caName + "/" + "openssl.cnf";;
        hash["DEBUG"] = "1";
        OPENSSL ossl(hash);

        hash.clear();
        hash["CAKEY"]   = repositoryDir + "/" + caName + "/cacert.key";
        hash["CACERT"]  = repositoryDir + "/" + caName + "/cacert.pem";;
        hash["PASSWD"]  = caPasswd;
        //hash[""] = "";
        
        ossl.updateDB(hash);
        ret = true;

    }
    return ret;
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
    if(!caRequestData.valid()) {
        LOGIT_ERROR("Invalid CA request data");
        BLOCXX_THROW(limal::ValueException, "Invalid CA request data");
    }

    if(!caIssueData.valid()) {
        LOGIT_ERROR("Invalid CA issue data");
        BLOCXX_THROW(limal::ValueException, "Invalid CA issue data");
    }
    

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

    // copy Section, because "req" is hard coded in openssl :-(
    tmpCA.getConfig()->copySection(type2Section(CA_Req, false), "req");

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
    hash["EXTENSION"] = "v3_req_ca";
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
    hash["EXTENSION"] = "v3_ca";

    k = ossl.createSelfSignedCert(hash);

    // some clean-ups 

    int r = path::copyFile(repos + "/" + caName + "/" + "cacert.pem",
                           repos + "/" + ".cas/" + caName + ".pem");
    
    if(r != 0) {
        LOGIT_INFO("Copy of cacert.pem to .cas/ failed: " << r);
    }
    
    StringArray cmd;
    cmd.push_back(C_REHASH_COMMAND);
    cmd.push_back(repos + "/" + ".cas/");

    blocxx::EnvVars env;
    env.addVar("PATH", "/usr/bin/");

    String stdOutput;
    String errOutput;
    int    status = 0;
    try {

        blocxx::Exec::executeProcessAndGatherOutput(cmd, stdOutput, errOutput, status, env);

    } catch(Exception& e) {
        LOGIT_INFO( "c_rehash exception:" << e);
        status = -1;
    }
    if(status != 0) {
        LOGIT_INFO( "c_rehash status:" << String(status));
    }
    if(!errOutput.empty()) {
        LOGIT_INFO("c_rehash stderr:" << errOutput);
    }
    if(!stdOutput.empty()) {
        LOGIT_DEBUG("c_rehash stdout:" << stdOutput);
    }

    return true;
}
       

bool
CA::importCA(const String& caName,
             const String& caCertificate,
             const String& cakey,
             const String& caPasswd,
             const String& repos)
{
    return false;
}


blocxx::Array<blocxx::String>
CA::getCAList(const String& repos)
{
    Array<String> caList;
    
    caList = listCA(repos);

    return caList;
}

        
blocxx::Array<blocxx::Array<blocxx::String> >
CA::getCATree(const String& repos)
{
    return blocxx::Array<blocxx::Array<blocxx::String> >();
}

CertificateIssueData
CA::getRootCAIssueDefaults(const String& repos)
{
    CAConfig *config = new CAConfig(repos+"/openssl.cnf.tmpl");
    CertificateIssueData cid = CertificateIssueData(config, CA_Cert);
    delete config;

    return cid;
}

RequestGenerationData
CA::getRootCARequestDefaults(const String& repos)
{
    CAConfig *config = new CAConfig(repos+"/openssl.cnf.tmpl");
    RequestGenerationData rgd = RequestGenerationData(config, CA_Req);
    delete config;

    return rgd;
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


blocxx::String
CA::checkDNPolicy(const DNObject& dn, Type type)
{
    // These types are not supported by this method
    if(type == Client_Req || type == Server_Req ||
       type == CA_Req     || type == CRL           ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = config->exists(type2Section(type, false), "policy");
    if(!p) {
        LOGIT_ERROR("missing value 'policy' in config file");
        BLOCXX_THROW(limal::SyntaxException, 
                     "missing value 'policy' in config file");
    }
    String policySect = config->getValue(type2Section(type, false), "policy");
    
    StringList policyKeys = config->getKeylist(policySect);
    
    if(policyKeys.empty()) {
        LOGIT_ERROR("Can not parse Section " << policySect);
        BLOCXX_THROW(limal::SyntaxException, 
                     Format("Can not parse Section %1", policySect).c_str());
    }
    StringList::const_iterator it = policyKeys.begin();
    
    blocxx::List<RDNObject> l = dn.getDN();

    bool policyFound = false;

    for(; it != policyKeys.end(); ++it) {

        policyFound = false;  // reset
        blocxx::List<RDNObject>::const_iterator rdnit = l.begin();

        for(; rdnit != l.end(); ++rdnit) {
        
            if( (*it).equalsIgnoreCase( (*rdnit).getType() ) ) {

                policyFound = true;

                // could be optional, supplied or match
                String policyString = config->getValue(policySect, *it);

                if(policyString.equalsIgnoreCase("optional")) {
                    // do not care
                } else if(policyString.equalsIgnoreCase("supplied")) {

                    if( (*rdnit).getValue().empty() ) {

                        return ("Invalid value for '" + *it + "'. This part has to have a value");

                    }

                } else if(policyString.equalsIgnoreCase("match")) {

                    // FIXME: read the CA and check the value

                } else {
                    LOGIT_ERROR("Invalid value for policy: "<< 
                                *it << "=" << policyString);
                    BLOCXX_THROW(limal::SyntaxException, 
                                 Format("Invalid value for policy: %1=%2", *it, policyString).c_str());
                }
            }
        }
        if(!policyFound) {

            // FIXME: do more
            LOGIT_ERROR("policy in config file but not in DN");

        }
    }
    return String();
}
