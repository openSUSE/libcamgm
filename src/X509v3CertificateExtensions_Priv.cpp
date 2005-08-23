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

  File:       X509v3CertificateExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include "X509v3CertificateExtensions_Priv.hpp"
#include <limal/Exception.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv()
    : X509v3CertificateExtensions()
{
}


X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv(X509* cert)
    : X509v3CertificateExtensions()
{
    // NsBaseUrlExtension         nsBaseUrl;

    parseStringExtension(cert, NID_netscape_base_url, nsBaseUrl);

    // NsRevocationUrlExtension   nsRevocationUrl;
    
    parseStringExtension(cert, NID_netscape_revocation_url, nsBaseUrl);

    // NsCaRevocationUrlExtension nsCaRevocationUrl;
    
    parseStringExtension(cert, NID_netscape_ca_revocation_url, nsBaseUrl);

    // NsRenewalUrlExtension      nsRenewalUrl;

    parseStringExtension(cert, NID_netscape_renewal_url, nsBaseUrl);

    // NsCaPolicyUrlExtension     nsCaPolicyUrl;

    parseStringExtension(cert, NID_netscape_ca_policy_url, nsBaseUrl);

    // NsSslServerNameExtension   nsSslServerName;

    parseStringExtension(cert, NID_netscape_ssl_server_name, nsBaseUrl);

    // NsCommentExtension         nsComment;

    parseStringExtension(cert, NID_netscape_comment, nsBaseUrl);

    // KeyUsageExtension   keyUsage;

    parseBitExtension(cert, NID_key_usage, keyUsage);

    // NsCertTypeExtension nsCertType;

    parseBitExtension(cert, NID_netscape_cert_type, nsCertType);

    // BasicConstraintsExtension       basicConstraints;

    parseBasicConstraintsExtension(cert, basicConstraints);

    // ExtendedKeyUsageExtension       extendedKeyUsage;

    parseExtKeyUsageExtension(cert, extendedKeyUsage);

    // SubjectKeyIdentifierExtension   subjectKeyIdentifier;

    // AuthorityKeyIdentifierExtension authorityKeyIdentifier;

    // SubjectAlternativeNameExtension subjectAlternativeName;

    // IssuerAlternativeNameExtension  issuerAlternativeName;

    // AuthorityInfoAccessExtension    authorityInfoAccess;

    // CRLDistributionPointsExtension  crlDistributionPoints;

    // CertificatePoliciesExtension    certificatePolicies;

}

X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv(const X509v3CertificateExtensions_Priv& extensions)
    : X509v3CertificateExtensions(extensions)
{
}


X509v3CertificateExtensions_Priv::~X509v3CertificateExtensions_Priv()
{
}

void
X509v3CertificateExtensions_Priv::setNsBaseUrl(const NsBaseUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsBaseUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsRevocationUrl(const NsRevocationUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCaRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsRenewalUrl(const NsRenewalUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsRenewalUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCaPolicyUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsSslServerName(const NsSslServerNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsSslServerName = ext;
}

void
X509v3CertificateExtensions_Priv::setNsComment(const NsCommentExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsComment = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCertType(const NsCertTypeExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCertType = ext;
}

void
X509v3CertificateExtensions_Priv::setKeyUsage(const KeyUsageExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    keyUsage = ext;
}

void
X509v3CertificateExtensions_Priv::setBasicConstraints(const BasicConstraintsExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    basicConstraints = ext;
}

void
X509v3CertificateExtensions_Priv::setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extendedKeyUsage = ext;
}

void
X509v3CertificateExtensions_Priv::setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    subjectKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    authorityKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Priv::setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    subjectAlternativeName = ext;
}

void
X509v3CertificateExtensions_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    issuerAlternativeName = ext;
}

void
X509v3CertificateExtensions_Priv::setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    authorityInfoAccess = ext;
}

void
X509v3CertificateExtensions_Priv::setCRLDistributionPoints(const CRLDistributionPointsExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    crlDistributionPoints = ext;
}

void
X509v3CertificateExtensions_Priv::setCertificatePolicies(const CertificatePoliciesExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    certificatePolicies = ext;
}


//    private:
X509v3CertificateExtensions_Priv&
X509v3CertificateExtensions_Priv::operator=(const X509v3CertificateExtensions_Priv& extensions)
{
    if(this == &extensions) return *this;
    
    X509v3CertificateExtensions::operator=(extensions);

    return *this;
}

void X509v3CertificateExtensions_Priv::parseStringExtension(X509* cert, 
                                                            int nid,
                                                            StringExtension &ext)
{
    int crit = 0;
    
    ASN1_STRING *str = NULL;
    str = static_cast<ASN1_STRING *>(X509_get_ext_d2i(cert, nid, &crit, NULL));
    
    if(str == NULL) {
        
        if(crit == -1) {
            // extension not found
            ext.setPresent(false);

            return;

        } else if(crit == -2) {
            // extension occurred more than once 
            LOGIT_ERROR("Extension occurred more than once: " << nid);
            BLOCXX_THROW(limal::SyntaxException,
                         Format("Extension occurred more than once: %1", nid).c_str());

        }

        LOGIT_ERROR("Unable to parse the certificate (NID:" << nid << " Crit:" << crit << ")");
        BLOCXX_THROW(limal::SyntaxException,
                     Format("Unable to parse the certificate (NID: %1 Crit: %2)", nid, crit).c_str());
    } 
    
    char *s = new char[str->length +1];
    memcpy(s, str->data, str->length);
    s[str->length] = '\0';

    ext.setValue(s);

    delete(s);

    if(crit == 1) {
        ext.setCritical(true);
    } else {
        ext.setCritical(false);
    }

    ASN1_STRING_free(str);
}

void X509v3CertificateExtensions_Priv::parseBitExtension(X509* cert, 
                                                         int nid,
                                                         BitExtension &ext)
{
    int crit = 0;
    
    ASN1_BIT_STRING *bit = NULL;
    bit = static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(cert, nid, &crit, NULL));
    
    if(bit == NULL) {
        
        if(crit == -1) {
            // extension not found
            ext.setPresent(false);

            return;

        } else if(crit == -2) {
            // extension occurred more than once 
            LOGIT_ERROR("Extension occurred more than once: " << nid);
            BLOCXX_THROW(limal::SyntaxException,
                         Format("Extension occurred more than once: %1", nid).c_str());

        }

        LOGIT_ERROR("Unable to parse the certificate (NID:" << nid << " Crit:" << crit << ")");
        BLOCXX_THROW(limal::SyntaxException,
                     Format("Unable to parse the certificate (NID: %1 Crit: %2)", nid, crit).c_str());
    } 
    
    int len = bit->length -1;
    UInt32 ret = 0;
    
    for(; len >= 0; --len) {
        
        int bits = bit->data[len];
        int shift = bits<<(len*8);
        ret |= shift;
    }
    
    ext.setValue(ret);

    if(crit == 1) {
        ext.setCritical(true);
    } else {
        ext.setCritical(false);
    }

    ASN1_STRING_free(bit);
}

void 
X509v3CertificateExtensions_Priv::parseExtKeyUsageExtension(X509* cert,
                                                            ExtendedKeyUsageExtension &ext)
{
    int crit = 0;
    
    EXTENDED_KEY_USAGE *eku = NULL;
    eku = static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(cert, NID_ext_key_usage, &crit, NULL));
    
    if(eku == NULL) {
        
        if(crit == -1) {
            // extension not found
            ext.setPresent(false);

            return;

        } else if(crit == -2) {
            // extension occurred more than once 
            LOGIT_ERROR("Extension occurred more than once");
            BLOCXX_THROW(limal::SyntaxException,
                         "Extension occurred more than once");

        }

        LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
        BLOCXX_THROW(limal::SyntaxException,
                     Format("Unable to parse the certificate (Crit: %2)", crit).c_str());
    }

    int i;
    ASN1_OBJECT *obj;
    char obj_tmp[80];
    StringList usageList;
    for(i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
        obj = sk_ASN1_OBJECT_value(eku, i);
        i2t_ASN1_OBJECT(obj_tmp, 80, obj);
        int nid = OBJ_txt2nid(obj_tmp);
        if(nid == 0) {
            usageList.push_back(obj_tmp);
        } else {
            usageList.push_back(String(OBJ_nid2sn(nid)));
        }
    }
    ext.setExtendedKeyUsage(usageList);

    EXTENDED_KEY_USAGE_free(eku);
}

void 
X509v3CertificateExtensions_Priv::parseBasicConstraintsExtension(X509* cert,
                                                                 BasicConstraintsExtension &ext)
{
    int crit = 0;
    
    BASIC_CONSTRAINTS *bs = NULL;
    bs = static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL));
    
    if(bs == NULL) {
        
        if(crit == -1) {
            // extension not found
            ext.setPresent(false);

            return;

        } else if(crit == -2) {
            // extension occurred more than once 
            LOGIT_ERROR("Extension occurred more than once");
            BLOCXX_THROW(limal::SyntaxException,
                         "Extension occurred more than once");

        }

        LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
        BLOCXX_THROW(limal::SyntaxException,
                     Format("Unable to parse the certificate (Crit: %2)", crit).c_str());
    }

    bool  ca = false;
    Int32 pl = -1;

    if(bs->ca) {

        ca = true;

        if(bs->pathlen) {
            if(bs->pathlen->type != V_ASN1_NEG_INTEGER) {

                pl = ASN1_INTEGER_get(bs->pathlen);
            }
        }
    }

    ext.setBasicConstraints(ca, pl);

    BASIC_CONSTRAINTS_free(bs);
}
