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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


CRLReason::CRLReason()
{
}

CRLReason::CRLReason(RevokeReason reason)
{
}

CRLReason::CRLReason(const CRLReason& reason)
{
}

CRLReason::~CRLReason()
{
}

CRLReason&
CRLReason::operator=(const CRLReason& reason)
{
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


// #####################################################################

CRLReasonHold::CRLReasonHold()
    : CRLReason()
{
}

CRLReasonHold::CRLReasonHold(const String& holdInstruction)
    : CRLReason()
{
}

CRLReasonHold::CRLReasonHold(const CRLReasonHold& reason)
    : CRLReason()
{
}

CRLReasonHold::~CRLReasonHold()
{
}

CRLReasonHold&
CRLReasonHold::operator=(const CRLReasonHold& reason)
{
    return *this;
}

void
CRLReasonHold::setHoldInstruction(const String& holdInstruction)
{
    this->holdInstruction = holdInstruction;
}

blocxx::String
CRLReasonHold::getHoldInstruction() const
{
    return holdInstruction;
}


// #####################################################################

CRLReasonKeyCompromise::CRLReasonKeyCompromise()
    : CRLReason()
{
}

CRLReasonKeyCompromise::CRLReasonKeyCompromise(time_t compromiseDate)
    : CRLReason()
{
}

CRLReasonKeyCompromise::CRLReasonKeyCompromise(const CRLReasonKeyCompromise& reason)
    : CRLReason()
{
}

CRLReasonKeyCompromise::~CRLReasonKeyCompromise()
{
}

CRLReasonKeyCompromise&
CRLReasonKeyCompromise::operator=(const CRLReasonKeyCompromise& reason)
{
    return *this;
}

void
CRLReasonKeyCompromise::setCompromiseDate(time_t compromiseDate)
{
    this->compromiseDate = compromiseDate;
}

time_t
CRLReasonKeyCompromise::getCompromiseDate() const
{
    return compromiseDate;
}

// #####################################################################

CRLReasonCaCompromise::CRLReasonCaCompromise()
    : CRLReason()
{
}

CRLReasonCaCompromise::CRLReasonCaCompromise(time_t compromiseDate)
    : CRLReason()
{
}

CRLReasonCaCompromise::CRLReasonCaCompromise(const CRLReasonCaCompromise& reason)
    : CRLReason()
{
}

CRLReasonCaCompromise::~CRLReasonCaCompromise()
{
}


CRLReasonCaCompromise&
CRLReasonCaCompromise::operator=(const CRLReasonCaCompromise& reason)
{
    return *this;
}

void
CRLReasonCaCompromise::setCompromiseDate(time_t compromiseDate)
{
    this->compromiseDate = compromiseDate;
}

time_t
CRLReasonCaCompromise::getCompromiseDate() const
{
    return compromiseDate;
}

