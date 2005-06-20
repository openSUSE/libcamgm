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
#include  "CertificateData_Priv.hpp"
#include  "RequestData_Priv.hpp"
#include  "CRLData_Priv.hpp"


using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CA::CA(const String& caName, const String& caPasswd)
    : caName(caName), caPasswd(caPasswd), 
      config(new CAConfig(String(REPOSITORY)+"/"+caName+"/openssl.cnf.tmpl"))
{
}

CA::~CA()
{
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
    return CertificateIssueData();
}

RequestGenerationData
CA::getRequestDefaults(Type type)
{
    return RequestGenerationData();
}


CRLGenerationData
CA::getCRLDefaults()
{
    return CRLGenerationData();
}

bool
CA::setIssueDefaults(Type type,
                     const CertificateIssueData& defaults)
{
    return false;
}

bool
CA::setRequestDefaults(Type type,
                       const RequestGenerationData& defaults)
{
    return false;
}

bool
CA::setCRLDefaults(const CRLGenerationData& defaults)
{
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



/* ##########################################################################
 * ###          static Functions                                          ###
 * ##########################################################################
 */

bool 
CA::createRootCA(const String& caName,
                 const String& caPasswd,
                 const RequestGenerationData& caRequestData,
                 const CertificateIssueData& caIssueData)
{
    return false;
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


