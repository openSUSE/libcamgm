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

  File:       LiteralValue_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "LiteralValues_Priv.hpp"

#include <openssl/asn1t.h>
#include <openssl/err.h>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;


namespace
{
typedef struct
{
	ASN1_INTEGER                 *nametype;
	STACK_OF(ASN1_GENERALSTRING) *namelist;
} KRB5_NAME;

typedef struct
{
	ASN1_GENERALSTRING   *realm;
	KRB5_NAME            *kerberosname;
} KRB5_PRINC_NAME;

ASN1_SEQUENCE(KRB5_NAME) = {
	ASN1_EXP(KRB5_NAME, nametype, ASN1_INTEGER, 0),
	ASN1_EXP_SEQUENCE_OF(KRB5_NAME, namelist, ASN1_GENERALSTRING , 1)
} ASN1_SEQUENCE_END(KRB5_NAME);


ASN1_SEQUENCE(KRB5_PRINC_NAME) = {
	ASN1_EXP(KRB5_PRINC_NAME, realm, ASN1_GENERALSTRING, 0),
	ASN1_EXP(KRB5_PRINC_NAME, kerberosname , KRB5_NAME, 1)
} ASN1_SEQUENCE_END(KRB5_PRINC_NAME);


IMPLEMENT_ASN1_FUNCTIONS(KRB5_NAME);
IMPLEMENT_ASN1_FUNCTIONS(KRB5_PRINC_NAME);

String asn1string2string(ASN1_STRING* str)
{
	char *s = new char[str->length +1];
	memcpy(s, str->data, str->length);
	s[str->length] = '\0';

	String ret(s);
	delete [] s;

	return ret;
}
}


LiteralValue_Priv::LiteralValue_Priv()
	: LiteralValue()
{}

LiteralValue_Priv::LiteralValue_Priv(GENERAL_NAME *gen)
	: LiteralValue()
{
	char oline[256];
	unsigned char *p = NULL;
	int nid = 0;

	ASN1_OBJECT *id_ms_san_upn;
	ASN1_OBJECT *id_pkinit_san;

#define CREATE_OBJ_IF_NEEDED(oid, vn, sn, ln)					\
	nid = OBJ_txt2nid(oid);										\
		if (nid == NID_undef) {									\
		nid = OBJ_create(oid, sn, ln);							\
		if (nid == NID_undef) {									\
		LOGIT_ERROR("Error creating oid object for " << oid);	\
		return;													\
}															    \
}																\
		vn = OBJ_nid2obj(nid);

	CREATE_OBJ_IF_NEEDED("1.3.6.1.5.2.2", id_pkinit_san,
	                     "id-pkinit-san", "KRB5PrincipalName");

	CREATE_OBJ_IF_NEEDED("1.3.6.1.4.1.311.20.2.3", id_ms_san_upn,
	                     "id-ms-san-upn", "Microsoft Universal Principal Name");

	switch (gen->type)
	{
	case GEN_EMAIL:
		setLiteral("email", asn1string2string(gen->d.ia5));
		break;

	case GEN_DNS:
		setLiteral("DNS", asn1string2string(gen->d.ia5));
		break;

	case GEN_URI:
		setLiteral("URI", asn1string2string(gen->d.ia5));
		break;

	case GEN_DIRNAME:
		X509_NAME_oneline(gen->d.dirn, oline, 256);
		setLiteral("DirName", oline);
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
		setLiteral("IP", oline);
		break;
	case GEN_RID:
		i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
		setLiteral("RID", oline);
		break;
	case GEN_OTHERNAME:
			// krb5PrincipalName || Microsoft Universal Principal Name
		if(OBJ_cmp(id_pkinit_san, gen->d.otherName->type_id) == 0)
		{
			decode_krb5_principal_name(gen->d.otherName->value->value.sequence->data,
			                           gen->d.otherName->value->value.sequence->length);
		}
		else if (OBJ_cmp(id_ms_san_upn, gen->d.otherName->type_id) == 0)
		{
			setLiteral("1.3.6.1.4.1.311.20.2.3", (char*)gen->d.otherName->value->value.sequence->data);
		}
		else
		{
			setLiteral("othername",
			           String("unsupported(") + String(OBJ_obj2nid(gen->d.otherName->type_id)) + ")");
		}
		break;
	case GEN_X400:
		setLiteral("X400Name", "unsupported");
		break;
	case GEN_EDIPARTY:
		setLiteral("EdiPartyName", "unsupported");
		break;
	}
}

LiteralValue_Priv::~LiteralValue_Priv()
{}


/* private */
void
LiteralValue_Priv::decode_krb5_principal_name(unsigned char* data, int len)
{
	KRB5_PRINC_NAME *pname = NULL;
	const unsigned char *p;
	p = data;

	pname = d2i_KRB5_PRINC_NAME(NULL, &p, len);

	if(pname == NULL ||
	   pname->realm == NULL ||
	   pname->kerberosname == NULL ||
	   pname->kerberosname->namelist == NULL)
	{
		//ERR_print_errors_fp(stderr);
		LOGIT_ERROR("Unable to decode KRB5PrincipalName");

		setLiteral("othername", String("unsupported(1.3.6.1.5.2.2)"));
		return;
	}

	String principal = "";

	for(int i = 0; i < sk_ASN1_GENERALSTRING_num(pname->kerberosname->namelist); i++)
	{
		//LOGIT_DEBUG( "NAMELIST" << i << ":" << asn1string2string(sk_ASN1_GENERALSTRING_value(pname->kerberosname->namelist, i)));
		if(principal == "")
		{
			principal += asn1string2string(sk_ASN1_GENERALSTRING_value(pname->kerberosname->namelist, i));
		}
		else
		{
			principal += "/" + asn1string2string(sk_ASN1_GENERALSTRING_value(pname->kerberosname->namelist, i));
		}
	}

	principal += "@" + asn1string2string(pname->realm);

	setLiteral("1.3.6.1.5.2.2", principal);
	p = NULL;
}

}
}
