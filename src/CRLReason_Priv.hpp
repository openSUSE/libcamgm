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

  File:       CRLReason_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_CRL_REASON_PRIV_HPP
#define    CA_MGM_CRL_REASON_PRIV_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/CRLReason.hpp>

#include  <openssl/x509.h>


namespace CA_MGM_NAMESPACE {

class CRLReason_Priv : public CRLReason {

public:
	CRLReason_Priv();
	CRLReason_Priv(STACK_OF(X509_EXTENSION) *stack);
	virtual ~CRLReason_Priv();

};

}


#endif /* CA_MGM_CRL_REASON_PRIV_HPP */
