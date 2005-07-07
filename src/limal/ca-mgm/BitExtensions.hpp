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

  File:       BitExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_BIT_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_BIT_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class BitExtension : public ExtensionBase {
    public:
        BitExtension();
        BitExtension(blocxx::UInt32 value);
        BitExtension(const BitExtension& extension);
        virtual ~BitExtension();

        BitExtension&  operator=(const BitExtension& extension);

        void           setValue(blocxx::UInt32 value);
        blocxx::UInt32 getValue() const;

        virtual void   commit2Config(CA& ca, Type type) const = 0;

        virtual bool                 valid() const  = 0;
        virtual blocxx::StringArray  verify() const = 0;

        virtual blocxx::StringArray  dump() const = 0;

    protected:
        blocxx::UInt32 value;

    };

    class KeyUsageExtension : public BitExtension {
    public:
        enum KeyUsage {
            digitalSignature  = 0x0001,
            nonRepudiation    = 0x0002,
            keyEncipherment   = 0x0004,
            dataEncipherment  = 0x0008,
            keyAgreement      = 0x0010,
            keyCertSign       = 0x0020,
            cRLSign           = 0x0040,
            encipherOnly      = 0x0080,
            decipherOnly      = 0x0100
        };
        
        KeyUsageExtension();
        KeyUsageExtension(CA& ca, Type type);
        KeyUsageExtension(blocxx::UInt32 keyUsage);
        KeyUsageExtension(const KeyUsageExtension& extension);
        virtual ~KeyUsageExtension();

        KeyUsageExtension& operator=(const KeyUsageExtension& extension);

        void           setKeyUsage(blocxx::UInt32 keyUsage);
        blocxx::UInt32 getKeyUsage() const;

        bool isEnabledFor(KeyUsage ku) const;

        virtual void commit2Config(CA& ca, Type type) const ;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        bool  validKeyUsage(blocxx::UInt32 keyUsage) const;
    };

    class NsCertTypeExtension : public BitExtension {
    public:
        enum NsCertType {
            client   = 0x0001,
            server   = 0x0002,
            email    = 0x0004,
            objsign  = 0x0008,
            reserved = 0x0010,
            sslCA    = 0x0020,
            emailCA  = 0x0040,
            objCA    = 0x0080
        };
        
        NsCertTypeExtension();
        NsCertTypeExtension(CA& ca, Type type);
        NsCertTypeExtension(blocxx::UInt32 nsCertTypes);
        NsCertTypeExtension(const NsCertTypeExtension& extension);
        virtual ~NsCertTypeExtension();

        NsCertTypeExtension& operator=(const NsCertTypeExtension& extension);

        void           setNsCertType(blocxx::UInt32 nsCertTypes);
        blocxx::UInt32 getNsCertType() const;
        
        bool           isEnabledFor(NsCertType nsCertType) const;

        virtual void   commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;
    };

    class ExtendedKeyUsageExtension : public BitExtension {
    public:
        enum ExtendedKeyUsage {
            serverAuth      = 0x0001,
            clientAuth      = 0x0002,
            codeSigning     = 0x0004,
            emailProtection = 0x0008,
            timeStamping    = 0x0010,
            msCodeInd       = 0x0020,
            msCodeCom       = 0x0040,
            msCTLSign       = 0x0080,
            msSGC           = 0x0100,
            msEFS           = 0x0200,
            nsSGC           = 0x0400,
        };

        ExtendedKeyUsageExtension();
        ExtendedKeyUsageExtension(CA& ca, Type type);
        ExtendedKeyUsageExtension(blocxx::UInt32 extKeyUsages, 
                                  const StringList& additionalOIDs = StringList());
        ExtendedKeyUsageExtension(const ExtendedKeyUsageExtension& extension);
        virtual ~ExtendedKeyUsageExtension();

        ExtendedKeyUsageExtension& operator=(const ExtendedKeyUsageExtension& extension);

        void                       setExtendedKeyUsage(blocxx::UInt32 extKeyUsages);
        blocxx::UInt32             getExtendedKeyUsage() const;
        
        bool                       isEnabledFor(ExtendedKeyUsage extKeyUsage) const;

        void                       setAdditionalOIDs(const StringList& additionalOIDs);
        StringList                 getAdditionalOIDs() const;

        void                       addAdditionalOID(String oid);
        //bool                       deleteAdditionalOID(String oid);

        virtual void               commit2Config(CA& ca, Type type) const;
        
        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    private:

        StringList oids;  //additional OIDs
    };

}
}

#endif // LIMAL_CA_MGM_BIT_EXTENSIONS_HPP
