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

  File:       CRLReason_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CRLReason_Priv.hpp"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/DateTime.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;


CRLReason_Priv::CRLReason_Priv()
    : CRLReason()
{}

CRLReason_Priv::CRLReason_Priv(STACK_OF(X509_EXTENSION) *stack)
    : CRLReason()
{
    for(int x = 0; x < sk_X509_EXTENSION_num(stack); x++)
    {        
        X509_EXTENSION *xe = sk_X509_EXTENSION_value(stack, x);

        int             nid = 0;
        String          valueString;
        char           *value;
        char            obj_tmp[80];
        BIO            *out;

        i2t_ASN1_OBJECT(obj_tmp, 80, xe->object);
        nid = OBJ_txt2nid(obj_tmp);
        
        LOGIT_DEBUG("NID: " << obj_tmp << " " << nid);
        
        out = BIO_new(BIO_s_mem());
        X509V3_EXT_print(out, xe, 0, 1);
        
        int n = BIO_get_mem_data(out, &value);
        valueString = String(value, n);
        valueString.ltrim();
        valueString.rtrim();
        BIO_free(out);

        LOGIT_DEBUG("Value: " << valueString);
        
        if(nid == NID_crl_reason)
        {            
            if(valueString == "Unspecified")
            {
                setReason("unspecified");
            }
            else if(valueString == "Key Compromise")
            {
                setReason("keyCompromise");
            }
            else if(valueString == "CA Compromise")
            {
                setReason("CACompromise");
            }
            else if(valueString == "Affiliation Changed")
            {
                setReason("affiliationChanged");
            }
            else if(valueString == "Superseded")
            {
                setReason("superseded");
            }
            else if(valueString == "Cessation Of Operation")
            {
                setReason("cessationOfOperation");
            }
            else if(valueString == "Certificate Hold")
            {
                setReason("certificateHold");
            }
            else if(valueString == "Remove From CRL")
            {
                setReason("removeFromCRL");
            }
            else
            {
                LOGIT_INFO("Unknown CRL reason:" << valueString);
            }
        }
        else if(nid == NID_hold_instruction_code)
        {            
            if(valueString == "Hold Instruction Call Issuer")
            {                
                setHoldInstruction("holdInstructionCallIssuer");
            }
            else if(valueString == "Hold Instruction None")
            {                
                setHoldInstruction("holdInstructionNone");
            }
            else if(valueString == "Hold Instruction Reject")
            {                
                setHoldInstruction("holdInstructionReject");
            }
            else
            {               
                // set an OID as hold instruction 
                setHoldInstruction(valueString);
            }
        }
        else if(nid == NID_invalidity_date)
        {            
            // e.g. Aug 18 15:56:46 2005 GMT
            DateTime dtime(valueString);
            
            if(getReason().equalsIgnoreCase("keyCompromise"))
            {                
                setKeyCompromiseDate(dtime.get());
            }
            else if(getReason().equalsIgnoreCase("CACompromise"))
            {
                setCACompromiseDate(dtime.get());
            }
            else
            {
                LOGIT_INFO("Date with wrong reason");
            }
            
        }
        else
        {
            LOGIT_INFO("Unsupported NID: " << nid);
        }
    }
}

CRLReason_Priv::~CRLReason_Priv()
{}

}
}
