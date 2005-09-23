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
    class CAConfig;

    /**
     * Base Class for Bit Extensions
     */
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

    /**
     * This extension describes the usage of this
     * certificate
     */
    class KeyUsageExtension : public BitExtension {
    public:
        enum KeyUsage {
            digitalSignature  = 0x0080, // KU_DIGITAL_SIGNATURE
            nonRepudiation    = 0x0040, // KU_NON_REPUDIATION
            keyEncipherment   = 0x0020, // KU_KEY_ENCIPHERMENT
            dataEncipherment  = 0x0010, // KU_DATA_ENCIPHERMENT
            keyAgreement      = 0x0008, // KU_KEY_AGREEMENT
            keyCertSign       = 0x0004, // KU_KEY_CERT_SIGN
            cRLSign           = 0x0002, // KU_CRL_SIGN
            encipherOnly      = 0x0001, // KU_ENCIPHER_ONLY
            decipherOnly      = 0x8000  // KU_DECIPHER_ONLY
        };
        
        KeyUsageExtension();
        KeyUsageExtension(CAConfig* caConfig, Type type);

        /**
         * Create an object with a specific key usage set
         */
        KeyUsageExtension(blocxx::UInt32 keyUsage);
        KeyUsageExtension(const KeyUsageExtension& extension);
        virtual ~KeyUsageExtension();

        KeyUsageExtension& operator=(const KeyUsageExtension& extension);

        /**
         * Set a new key usage
         */
        void           setKeyUsage(blocxx::UInt32 keyUsage);

        /**
         * Return the key usage
         */
        blocxx::UInt32 getKeyUsage() const;

        /**
         * Return true if the specified bit is set
         */
        bool isEnabledFor(KeyUsage ku) const;

        /**
         * Write the informations of this object back to the configuration file
         *
         * @param ca the CA object which holds the config object
         * @param type the type describes the section of the config file
         */
        virtual void commit2Config(CA& ca, Type type) const ;

        /**
         * Check if this object is valid
         *
         * @return true if this object is valid, otherwise false
         */
        virtual bool                 valid() const;

        /**
         * Verify this object and return an Array with all
         * error messages.
         *
         * @return Array with error messages. If this Array is empty this
         * object is valid
         */
        virtual blocxx::StringArray  verify() const;

        /**
         * Return the content of this object for debugging
         */
        virtual blocxx::StringArray  dump() const;

    private:
        bool  validKeyUsage(blocxx::UInt32 keyUsage) const;
    };

    /**
     * This extension describes the usage of this
     * certificate (Netscape specific)
     */
    class NsCertTypeExtension : public BitExtension {
    public:
        enum NsCertType {
            client   = 0x0080, // NS_SSL_CLIENT
            server   = 0x0040, // NS_SSL_SERVER
            email    = 0x0020, // NS_SMIME
            objsign  = 0x0010, // NS_OBJSIGN
            reserved = 0x0008, // ??
            sslCA    = 0x0004, // NS_SSL_CA
            emailCA  = 0x0002, // NS_SMIME_CA
            objCA    = 0x0001  // NS_OBJSIGN_CA
        };
        
        NsCertTypeExtension();
        NsCertTypeExtension(CAConfig* caConfig, Type type);

        /**
         * Create an object with a specific certificate type set
         */
        NsCertTypeExtension(blocxx::UInt32 nsCertTypes);
        NsCertTypeExtension(const NsCertTypeExtension& extension);
        virtual ~NsCertTypeExtension();

        NsCertTypeExtension& operator=(const NsCertTypeExtension& extension);

        /**
         * Set a new certificate type
         */
        void           setNsCertType(blocxx::UInt32 nsCertTypes);

        /**
         * Return the certificate type
         */
        blocxx::UInt32 getNsCertType() const;
        
        /**
         * Return true if the specified bit is set
         */
        bool           isEnabledFor(NsCertType nsCertType) const;

        /**
         * Write the informations of this object back to the configuration file
         *
         * @param ca the CA object which holds the config object
         * @param type the type describes the section of the config file
         */
        virtual void   commit2Config(CA& ca, Type type) const;

        /**
         * Check if this object is valid
         *
         * @return true if this object is valid, otherwise false
         */
        virtual bool                 valid() const;

        /**
         * Verify this object and return an Array with all
         * error messages.
         *
         * @return Array with error messages. If this Array is empty this
         * object is valid
         */
        virtual blocxx::StringArray  verify() const;

        /**
         * Return the content of this object for debugging
         */
        virtual blocxx::StringArray  dump() const;
    };

    /**
     * This extensions consists of a list of usages.
     *
     * These can either be object short names of the dotted
     * numerical form of OIDs.
     */
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
        ExtendedKeyUsageExtension(CAConfig* caConfig, Type type);

        /**
         * Create an object with the specified bit field and
         * a List of additional OIDs
         */
        ExtendedKeyUsageExtension(blocxx::UInt32 extKeyUsages, 
                                  const StringList& additionalOIDs = StringList());
        ExtendedKeyUsageExtension(const ExtendedKeyUsageExtension& extension);
        virtual ~ExtendedKeyUsageExtension();

        ExtendedKeyUsageExtension& operator=(const ExtendedKeyUsageExtension& extension);

        /**
         * Set new extended key usage.
         *
         * @param usageList this list can contain the short names or long OIDs
         * <ul>
         *   <li>serverAuth</li>
         *   <li>clientAuth</li>
         *   <li>codeSigning</li>
         *   <li>emailProtection</li>
         *   <li>timeStamping</li>
         *   <li>msCodeInd</li>
         *   <li>msCodeCom</li>
         *   <li>msCTLSign</li>
         *   <li>msSGC</li>
         *   <li>msEFS</li>
         *   <li>nsSGC</li>
         *   <li>1.5.2.6</li>
         * </ul>
         */
        void                       setExtendedKeyUsage(const StringList& usageList);

        /**
         * Set a new bit mask
         */
        void                       setExtendedKeyUsage(blocxx::UInt32 extKeyUsages);

        /**
         * Return the bit mask
         */
        blocxx::UInt32             getExtendedKeyUsage() const;

        /**
         * Return true if the specified bit is set
         */
        bool                       isEnabledFor(ExtendedKeyUsage extKeyUsage) const;

        /**
         * Set a new OID list
         */
        void                       setAdditionalOIDs(const StringList& additionalOIDs);

        /**
         * Return the OID List
         */
        StringList                 getAdditionalOIDs() const;

        /**
         * Append an OID to the list
         */
        void                       addAdditionalOID(String oid);
        //bool                       deleteAdditionalOID(String oid);

        /**
         * Write the informations of this object back to the configuration file
         *
         * @param ca the CA object which holds the config object
         * @param type the type describes the section of the config file
         */
        virtual void               commit2Config(CA& ca, Type type) const;
        
        /**
         * Check if this object is valid
         *
         * @return true if this object is valid, otherwise false
         */
        virtual bool                 valid() const;

        /**
         * Verify this object and return an Array with all
         * error messages.
         *
         * @return Array with error messages. If this Array is empty this
         * object is valid
         */
        virtual blocxx::StringArray  verify() const;

        /**
         * Return the content of this object for debugging
         */
        virtual blocxx::StringArray  dump() const;

    private:

        StringList oids;  //additional OIDs
    };

}
}

#endif // LIMAL_CA_MGM_BIT_EXTENSIONS_HPP
