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

// ----------------------------------------------------------------------------
    
CRLReason::CRLReason()
    : reason("none"), compromiseDate(0),
      holdInstruction("holdInstructionNone")
{
}

// ----------------------------------------------------------------------------

CRLReason::CRLReason(const String& reason)
    : compromiseDate(0),
      holdInstruction("holdInstructionNone")
{
    if(!checkReason(reason))
    {
        BLOCXX_THROW(limal::ValueException,
                     Format("Invalid revoke reason: %1", reason).c_str());
    }
    this->reason = reason;
}

// ----------------------------------------------------------------------------

CRLReason::CRLReason(const CRLReason& reason)
    : reason(reason.reason), compromiseDate(reason.compromiseDate),
      holdInstruction(reason.holdInstruction)
{
}

// ----------------------------------------------------------------------------

CRLReason::~CRLReason()
{}

// ----------------------------------------------------------------------------

CRLReason&
CRLReason::operator=(const CRLReason& reason)
{
    if(this == &reason) return *this;
    
    this->reason    = reason.reason;
    compromiseDate  = reason.compromiseDate;
    holdInstruction = reason.holdInstruction;
    
    return *this;
}

// ----------------------------------------------------------------------------

void
CRLReason::setReason(const String& reason)
{
    if(!checkReason(reason))
    {
        BLOCXX_THROW(limal::ValueException,
                     Format("Invalid revoke reason: %1", reason).c_str());
    }
    this->reason = reason;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getReason() const
{
    return reason;
}

// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getHoldInstruction() const
{
    if(!reason.equalsIgnoreCase("certificateHold"))
    {
        LOGIT_ERROR("Reason is not certificateHold");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not certificateHold");
    }
    return holdInstruction;
}

// ----------------------------------------------------------------------------

void
CRLReason::setKeyCompromiseDate(time_t compromiseDate)
{
    this->compromiseDate  = compromiseDate;
}

// ----------------------------------------------------------------------------

time_t
CRLReason::getKeyCompromiseDate() const
{
    if(!reason.equalsIgnoreCase("keyCompromise"))
    {
        LOGIT_ERROR("Reason is not keyCompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not keyCompromise");
    }
    return compromiseDate;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getKeyCompromiseDateAsString() const
{
    if(!reason.equalsIgnoreCase("keyCompromise"))
    {
        LOGIT_ERROR("Reason is not keyCompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not keyCompromise");
    }
    DateTime dt(compromiseDate);
    String time = dt.toString("%Y%m%d%H%M%S") + "Z";

    return time;
}

// ----------------------------------------------------------------------------

void
CRLReason::setCACompromiseDate(time_t compromiseDate)
{
    this->compromiseDate  = compromiseDate;
}

// ----------------------------------------------------------------------------

time_t
CRLReason::getCACompromiseDate() const
{
    if(!reason.equalsIgnoreCase("CACompromise"))
    {
        LOGIT_ERROR("Reason is not CACompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not CACompromise");
    }
    return compromiseDate;
}

// ----------------------------------------------------------------------------

blocxx::String
CRLReason::getCACompromiseDateAsString() const
{
    if(!reason.equalsIgnoreCase("CACompromise"))
    {
        LOGIT_ERROR("Reason is not CACompromise");
        BLOCXX_THROW(limal::RuntimeException, "Reason is not CACompromise");
    }
    DateTime dt(compromiseDate);
    String time = dt.toString("%Y%m%d%H%M%S") + "Z";

    return time;
}

// ----------------------------------------------------------------------------

bool
CRLReason::valid() const
{
    if(reason.equalsIgnoreCase("certificateHold"))
    {
        String r = checkHoldInstruction(holdInstruction);
        if(!r.empty()) {
            LOGIT_DEBUG(r);
            return false;
        }
    }
    else if(reason.equalsIgnoreCase("keyCompromise") ||
            reason.equalsIgnoreCase("CACompromise"))
    {
        if(compromiseDate == 0) {
            LOGIT_DEBUG("invalid compromiseDate");
            return false;
        }
    }
    return checkReason(reason);
}

// ----------------------------------------------------------------------------

blocxx::StringArray
CRLReason::verify() const
{
    StringArray result;

    if(reason.equalsIgnoreCase("certificateHold"))
    {
        String err = checkHoldInstruction(holdInstruction);
        if(!err.empty()) {
            result.append(err);
        }
    }
    else if(reason.equalsIgnoreCase("keyCompromise") ||
            reason.equalsIgnoreCase("CACompromise"))
    {
        if(compromiseDate == 0) {
            result.append(Format("invalid compromiseDate: %1",
                                 String(compromiseDate)));
        }
    }
    else if(!checkReason(reason))
    {
        result.append(Format("Invalid revoke reason", reason));
    }
    
    LOGIT_DEBUG_STRINGARRAY("CRLReason::verify()", result);
    return result;
}

// ----------------------------------------------------------------------------

blocxx::StringArray
CRLReason::dump() const
{
    StringArray result;
    result.append("CRLReason::dump()");

    if(reason.equalsIgnoreCase("certificateHold"))
    {
        result.append("Revoke Reason = certificateHold");
        result.append("hold Instruction =" + holdInstruction);
    }
    else if(reason.equalsIgnoreCase("keyCompromise") ||
            reason.equalsIgnoreCase("CACompromise"))
    {
        result.append(Format("Revoke Reason = %1", reason));
        result.append("compromise Date = " + String(compromiseDate));
    }
    else
    {
        result.append("Revoke Reason = " + String(reason));
    } 
    
    return result;
}

// ----------------------------------------------------------------------------
// private:
// ----------------------------------------------------------------------------

blocxx::String
CRLReason::checkHoldInstruction(const String& hi) const
{
    if(!hi.equalsIgnoreCase("holdInstructionNone")       &&
       !hi.equalsIgnoreCase("holdInstructionCallIssuer") &&
       !hi.equalsIgnoreCase("holdInstructionReject")     &&
       !initOIDCheck().isValid(hi)) {
        
        return (Format("Invalid holdInstruction: %1", hi).toString());
    }
    return String();
}

// ----------------------------------------------------------------------------

bool
CRLReason::checkReason(const String& reason) const
{
    if(reason.equalsIgnoreCase("none")                 ||
       reason.equalsIgnoreCase("unspecified")          ||
       reason.equalsIgnoreCase("keyCompromise")        ||
       reason.equalsIgnoreCase("CACompromise")         ||
       reason.equalsIgnoreCase("affiliationChanged")   ||
       reason.equalsIgnoreCase("superseded")           ||
       reason.equalsIgnoreCase("cessationOfOperation") ||
       reason.equalsIgnoreCase("certificateHold")      ||
       reason.equalsIgnoreCase("removeFromCRL"))
    {
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
    
}
}
