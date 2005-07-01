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

  File:       CRLReason.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_REASON_HPP
#define    LIMAL_CA_MGM_CRL_REASON_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {


    class CRLReason {
    public:
        enum RevokeReason {
            none,
            unspecified,
            keyCompromise,
            CACompromise,
            affiliationChanged,
            superseded,
            cessationOfOperation,
            certificateHold,
            removeFromCRL
        };

        CRLReason();
        CRLReason(RevokeReason reason);
        CRLReason(const CRLReason& reason);
        virtual ~CRLReason();

        CRLReason& operator=(const CRLReason& reason);

        void         setReason(RevokeReason reason);
        RevokeReason getReason() const;

        void   setHoldInstruction(const String& holdInstruction);
        String getHoldInstruction() const;

        void   setKeyCompromiseDate(time_t compromiseDate);
        time_t getKeyCompromiseDate() const;

        void   setCACompromiseDate(time_t compromiseDate);
        time_t getCACompromiseDate() const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

    private:

        RevokeReason reason;

        // used if reason is keyCompromise or CACompromise,

        time_t compromiseDate;

        // used if reason is certificateHold
        // possible values: 
        //    holdInstructionNone,
        //    holdInstructionCallIssuer, 
        //    holdInstructionReject
        // or an OID
        String holdInstruction;
        
    };

}
}

#endif // LIMAL_CA_MGM_CRL_REASON_HPP
