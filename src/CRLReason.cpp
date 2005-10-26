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

  File:       CRLReason.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLReason.hpp>
#include  <limal/ValueRegExCheck.hpp>
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

CRLReason::CRLReason()
    : reason(none), compromiseDate(0),
      holdInstruction("holdInstructionNone")
{
}

CRLReason::CRLReason(RevokeReason reason)
    : reason(reason), compromiseDate(0),
      holdInstruction("holdInstructionNone")
{
}

CRLReason::CRLReason(const CRLReason& reason)
    : reason(reason.reason), compromiseDate(reason.compromiseDate),
      holdInstruction(reason.holdInstruction)
{
}

CRLReason::~CRLReason()
{}

CRLReason&
CRLReason::operator=(const CRLReason& reason)
{
    if(this == &reason) return *this;
    
    this->reason    = reason.reason;
    compromiseDate  = reason.compromiseDate;
    holdInstruction = reason.holdInstruction;
    
    return *this;
}

void
CRLReason::setReason(CRLReason::RevokeReason reason)
{
    this->reason = reason;
}

CRLReason::RevokeReason
CRLReason::getReason() const
{
    return reason;
}

blocxx::String
CRLReason::getReasonAsString() const
{
    switch( reason ) {
    case unspecified:
        return "unspecified";
        break;
    case keyCompromise:
        return "keyCompromise";
        break;
    case CACompromise:
        return "CACompromise";
        break;
    case affiliationChanged:
        return "affiliationChanged";
        break;
    case superseded:
        return "superseded";
        break;
    case cessationOfOperation:
        return "cessationOfOperation";
        break;
    case certificateHold:
        return "certificateHold";
        break;
    case removeFromCRL:
        return "removeFromCRL";
        break;
    default:
        return "none";
    }    
}


void
CRLReason::setHoldInstruction(const String& holdInstruction)
{
    String r = checkHoldInstruction(holdInstruction);
    if(!r.empty()) {
        LOGIT_ERROR(r);
        BLOCXX_THROW(limal::ValueException, r.c_str());
    }

    this->holdInstruction = holdInstruction;
}

blocxx::String
CRLReason::getHoldInstruction() const
{
    if(reason != CRLReason::certificateHold) {
        LOGIT_ERROR("Reason is not certificateHold");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not certificateHold");
    }
    return holdInstruction;
}


void
CRLReason::setKeyCompromiseDate(time_t compromiseDate)
{
    this->compromiseDate  = compromiseDate;
}

time_t
CRLReason::getKeyCompromiseDate() const
{
    if(reason != CRLReason::keyCompromise) {
        LOGIT_ERROR("Reason is not keyCompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not keyCompromise");
    }
    return compromiseDate;
}

blocxx::String
CRLReason::getKeyCompromiseDateAsString() const
{
    if(reason != CRLReason::keyCompromise) {
        LOGIT_ERROR("Reason is not keyCompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not keyCompromise");
    }
    DateTime dt(compromiseDate);
    String time = dt.toString("%Y%m%d%H%M%S") + "Z";

    return time;
}

void
CRLReason::setCACompromiseDate(time_t compromiseDate)
{
    this->compromiseDate  = compromiseDate;
}

time_t
CRLReason::getCACompromiseDate() const
{
    if(reason != CRLReason::CACompromise) {
        LOGIT_ERROR("Reason is not CACompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not CACompromise");
    }
    return compromiseDate;
}

blocxx::String
CRLReason::getCACompromiseDateAsString() const
{
    if(reason != CRLReason::CACompromise) {
        LOGIT_ERROR("Reason is not CACompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not CACompromise");
    }
    DateTime dt(compromiseDate);
    String time = dt.toString("%Y%m%d%H%M%S") + "Z";

    return time;
}

bool
CRLReason::valid() const
{
    String r;

    switch(reason) {
    case CRLReason::certificateHold:
        r = checkHoldInstruction(holdInstruction);
        if(!r.empty()) {
            LOGIT_DEBUG(r);
            return false;
        }
        break;
    case CRLReason::keyCompromise:
    case CRLReason::CACompromise:
        if(compromiseDate == 0) {
            LOGIT_DEBUG("invalid compromiseDate");
            return false;
        }
        break;
    default:
        return true;
    }
    return true;
}

blocxx::StringArray
CRLReason::verify() const
{
    StringArray result;
    String err;

    switch(reason) {
    case CRLReason::certificateHold:
        err = checkHoldInstruction(holdInstruction);
        if(!err.empty()) {
            result.append(err);
        }
        break;
    case CRLReason::keyCompromise:
    case CRLReason::CACompromise:
        if(compromiseDate == 0) {
            result.append("invalid compromiseDate");
        }
        break;
    default:
        break;
    } 

    LOGIT_DEBUG_STRINGARRAY("CRLReason::verify()", result);
    return result;
}

blocxx::StringArray
CRLReason::dump() const
{
    StringArray result;
    result.append("CRLReason::dump()");

    switch(reason) {
    case CRLReason::certificateHold:
        result.append("Revoke Reason = certificateHold");
        result.append("hold Instruction =" + holdInstruction);

        break;
    case CRLReason::keyCompromise:
        result.append("Revoke Reason = keyCompromise");
        result.append("compromise Date =" + String(compromiseDate));
        break;
    case CRLReason::CACompromise:
        result.append("Revoke Reason = CACompromise");
        result.append("compromise Date =" + String(compromiseDate));
        break;
    default:
        result.append("Revoke Reason = " + String(reason));
        break;
    } 

    return result;
}


blocxx::String
CRLReason::checkHoldInstruction(const String& hi) const
{
    if(hi != "holdInstructionNone"       &&
       hi != "holdInstructionCallIssuer" &&
       hi != "holdInstructionReject"     &&
       !initOIDCheck().isValid(hi)) {
        
        return (Format("Invalid holdInstruction: %1", hi).toString());
    }
    return String();
}

}
}
