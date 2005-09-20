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

  File:       X509v3CRLExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "X509v3CRLExtensions_Priv.hpp"
#include  <limal/Exception.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  "Utils.hpp"
#include  "AuthorityKeyIdentifierExtension_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

inline static LiteralValue gn2lv(GENERAL_NAME *gen)
{
    char oline[256];
    char *s = NULL;
    unsigned char *p;
    LiteralValue lv;

    switch (gen->type) {
        
    case GEN_EMAIL:
        s = new char[gen->d.ia5->length +1];
        memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
        s[gen->d.ia5->length] = '\0';
        lv.setLiteral("email", s);
        delete [] s;
        break;

    case GEN_DNS:
        s = new char[gen->d.ia5->length +1];
        memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
        s[gen->d.ia5->length] = '\0';
        lv.setLiteral("DNS", s);
        delete [] s;
        break;

    case GEN_URI:
        s = new char[gen->d.ia5->length +1];
        memcpy(s, gen->d.ia5->data, gen->d.ia5->length);
        s[gen->d.ia5->length] = '\0';
        lv.setLiteral("URI", s);
        delete [] s;
        break;

    case GEN_DIRNAME:
        X509_NAME_oneline(gen->d.dirn, oline, 256);
        lv.setLiteral("DirName", oline);
        break;

    case GEN_IPADD:
        p = gen->d.ip->data;
        /* BUG: doesn't support IPV6 */
        if(gen->d.ip->length != 4) {
            LOGIT_ERROR("Invalid IP Address: maybe IPv6");
            BLOCXX_THROW(limal::SyntaxException, "Invalid IP Address: maybe IPv6");
            break;
        }
        BIO_snprintf(oline, sizeof oline,
                     "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        lv.setLiteral("IP", oline);
        break;

    case GEN_RID:
        i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
        lv.setLiteral("RID", oline);
        break;
    }
    return lv;
}

X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv()
    : X509v3CRLExtensions()
{
}

X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv(STACK_OF(X509_EXTENSION) *extensions)
    : X509v3CRLExtensions()
{

    // AuthorityKeyIdentifierExtension authorityKeyIdentifier;

    authorityKeyIdentifier = AuthorityKeyIdentifierExtension_Priv(extensions);

    // IssuerAlternativeNameExtension  issuerAlternativeName;

    parseIssuerAlternativeNameExtension(extensions, issuerAlternativeName);

}

X509v3CRLExtensions_Priv::X509v3CRLExtensions_Priv(const X509v3CRLExtensions_Priv& extensions)
    : X509v3CRLExtensions(extensions)
{
}


X509v3CRLExtensions_Priv::~X509v3CRLExtensions_Priv()
{
}

void
X509v3CRLExtensions_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    authorityKeyIdentifier = ext;
}

void
X509v3CRLExtensions_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    issuerAlternativeName = ext;
}


//  private:
X509v3CRLExtensions_Priv&
X509v3CRLExtensions_Priv::operator=(const X509v3CRLExtensions_Priv& extensions)
{
    if(this == &extensions) return *this;
    
    X509v3CRLExtensions::operator=(extensions);

    return *this;
}

void 
X509v3CRLExtensions_Priv::parseIssuerAlternativeNameExtension(STACK_OF(X509_EXTENSION) *cert,
                                                              IssuerAlternativeNameExtension &ext)
{
    int crit = 0;
    
    GENERAL_NAMES *gns = NULL;
    gns = static_cast<GENERAL_NAMES *>(X509V3_get_d2i(cert, NID_issuer_alt_name, &crit, NULL));
    
    if(gns == NULL) {
        
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
    
    int j;
    GENERAL_NAME *gen;
    blocxx::List<LiteralValue> lvList;

    for(j = 0; j < sk_GENERAL_NAME_num(gns); j++) {

        gen = sk_GENERAL_NAME_value(gns, j);

        LiteralValue lv = gn2lv(gen);

        lvList.push_back(lv);
    }

    if(crit == 1) {
        ext.setCritical(true);
    } else {
        ext.setCritical(false);
    }

    if(!lvList.empty()) {

        ext.setCopyIssuer(false);
        ext.setAlternativeNameList(lvList);

    } else {

        ext.setPresent(false);

    }

    GENERAL_NAMES_free(gns);
}
