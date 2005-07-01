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

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

inline static ValueCheck initOIDCheck() {
    ValueCheck checkOID =
        ValueCheck(new ValuePosixRECheck("^([0-9]+\\.)+[0-9]+$"));

    return checkOID;
}

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
    RevokeReason oldReason = this->reason;

    this->reason = reason;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->reason = oldReason;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

CRLReason::RevokeReason
CRLReason::getReason() const
{
    return reason;
}

void
CRLReason::setHoldInstruction(const String& holdInstruction)
{
    RevokeReason oldReason = this->reason;
    String       oldInst   = holdInstruction;

    this->reason          = CRLReason::certificateHold;
    this->holdInstruction = holdInstruction;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->reason = oldReason;
        this->holdInstruction = oldInst;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::String
CRLReason::getHoldInstruction() const
{
    if(reason != CRLReason::certificateHold) {
        LOGIT_DEBUG("reason is not certificateHold");
        BLOCXX_THROW(limal::RuntimeException, "reason is not certificateHold");
    }
    return holdInstruction;
}


void
CRLReason::setKeyCompromiseDate(time_t compromiseDate)
{
    RevokeReason oldReason = this->reason;
    time_t       oldDate   = compromiseDate;

    this->reason          = CRLReason::keyCompromise;
    this->compromiseDate  = compromiseDate;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->reason         = oldReason;
        this->compromiseDate = oldDate;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

time_t
CRLReason::getKeyCompromiseDate() const
{
    if(reason != CRLReason::keyCompromise) {
        LOGIT_DEBUG("reason is not keyCompromise");
        BLOCXX_THROW(limal::RuntimeException, "reason is not keyCompromise");
    }
    return compromiseDate;
}

void
CRLReason::setCACompromiseDate(time_t compromiseDate)
{
    RevokeReason oldReason = this->reason;
    time_t       oldDate   = compromiseDate;

    this->reason          = CRLReason::CACompromise;
    this->compromiseDate  = compromiseDate;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        this->reason         = oldReason;
        this->compromiseDate = oldDate;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

time_t
CRLReason::getCACompromiseDate() const
{
    if(reason != CRLReason::CACompromise) {
        LOGIT_DEBUG("reason is not CACompromise");
        BLOCXX_THROW(limal::RuntimeException, "reason is not CACompromise");
    }
    return compromiseDate;
}

bool
CRLReason::valid() const
{
    ValueCheck check = initOIDCheck();

    switch(reason) {
    case CRLReason::certificateHold:
        if(holdInstruction != "holdInstructionNone" ||
           holdInstruction != "holdInstructionCallIssuer" ||
           holdInstruction != "holdInstructionReject" ||
           !check.isValid(holdInstruction)) {

            LOGIT_DEBUG("invalid holdInstruction: " << holdInstruction);
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
    ValueCheck check = initOIDCheck();
    
    switch(reason) {
    case CRLReason::certificateHold:
        if(holdInstruction != "holdInstructionNone" ||
           holdInstruction != "holdInstructionCallIssuer" ||
           holdInstruction != "holdInstructionReject" ||
           !check.isValid(holdInstruction)) {
            
            result.append(Format("invalid holdInstruction: ", holdInstruction).toString());
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
