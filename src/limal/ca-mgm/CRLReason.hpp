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

    private:

        RevokeReason reason;
        
    };

    class CRLReasonHold: public CRLReason {
    public:
        CRLReasonHold();
        CRLReasonHold(const String& holdInstruction);
        CRLReasonHold(const CRLReasonHold& reason);
        virtual ~CRLReasonHold();

        CRLReasonHold& operator=(const CRLReasonHold& reason);

        void   setHoldInstruction(const String& holdInstruction);
        String getHoldInstruction() const;


    private:
        // possible values: 
        //    holdInstructionNone,
        //    holdInstructionCallIssuer, 
        //    holdInstructionReject
        // or an OID
        String holdInstruction;
    };

    class CRLReasonKeyCompromise: public CRLReason {
    public:
        CRLReasonKeyCompromise();
        CRLReasonKeyCompromise(time_t compromiseDate);
        CRLReasonKeyCompromise(const CRLReasonKeyCompromise& reason);
        virtual ~CRLReasonKeyCompromise();

        CRLReasonKeyCompromise& operator=(const CRLReasonKeyCompromise& reason);

        void   setCompromiseDate(time_t compromiseDate);
        time_t getCompromiseDate() const;

    private:
        time_t compromiseDate;
    };

    class CRLReasonCaCompromise: public CRLReason {
    public:
        CRLReasonCaCompromise();
        CRLReasonCaCompromise(time_t compromiseDate);
        CRLReasonCaCompromise(const CRLReasonCaCompromise& reason);
        virtual ~CRLReasonCaCompromise();

        CRLReasonCaCompromise& operator=(const CRLReasonCaCompromise& reason);

        void   setCompromiseDate(time_t compromiseDate);
        time_t getCompromiseDate() const;

    private:
        time_t compromiseDate;
    };

}
}

#endif // LIMAL_CA_MGM_CRL_REASON_HPP
