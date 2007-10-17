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

  File:       LiteralValues_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_LITERAL_VALUE_PRIV_HPP
#define    LIMAL_CA_MGM_LITERAL_VALUE_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>
#include  <limal/ByteBuffer.hpp>

#include  <openssl/x509v3.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

class LiteralValue_Priv : public LiteralValue {

public:
	LiteralValue_Priv();
	LiteralValue_Priv(GENERAL_NAME *gen);
	virtual ~LiteralValue_Priv();

private:
	void decode_krb5_principal_name(unsigned char* data, int len);
};

}
}


#endif /* LIMAL_CA_MGM_CRL_REASON_PRIV_HPP */
