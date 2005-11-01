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

  File:       ExtendedKeyUsageExt.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_EXTENDED_KEY_USAGE_EXT_HPP
#define    LIMAL_CA_MGM_EXTENDED_KEY_USAGE_EXT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    /**
     * This extensions consists of a list of usages.
     *
     * These can either be object short names of the dotted
     * numerical form of OIDs.
     */
    class ExtendedKeyUsageExt : public ExtensionBase {
    public:
        ExtendedKeyUsageExt();
        ExtendedKeyUsageExt(CAConfig* caConfig, Type type);

        /**
         * Create an object with the specified bit field and
         * a List of additional OIDs
         */
        ExtendedKeyUsageExt(const StringList& extKeyUsages);
        
        ExtendedKeyUsageExt(const ExtendedKeyUsageExt& extension);
        
        virtual ~ExtendedKeyUsageExt();

        ExtendedKeyUsageExt&
        operator=(const ExtendedKeyUsageExt& extension);

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
        void
        setExtendedKeyUsage(const StringList& usageList);


        /**
         * Return the list of extended keyusages 
         */
        StringList
        getExtendedKeyUsage() const;

        /**
         * Return true if the specified usage is set
         */
        bool
        isEnabledFor(const String& extKeyUsage) const;


        /**
         * Write the informations of this object back to the configuration file
         *
         * @param ca the CA object which holds the config object
         * @param type the type describes the section of the config file
         */
        virtual void
        commit2Config(CA& ca, Type type) const;
        
        /**
         * Check if this object is valid
         *
         * @return true if this object is valid, otherwise false
         */
        virtual bool
        valid() const;

        /**
         * Verify this object and return an Array with all
         * error messages.
         *
         * @return Array with error messages. If this Array is empty this
         * object is valid
         */
        virtual blocxx::StringArray
        verify() const;

        /**
         * Return the content of this object for debugging
         */
        virtual blocxx::StringArray
        dump() const;

    private:

        StringList usage;

        bool
        checkValue(const String& value) const;

    };

}
}

#endif //LIMAL_CA_MGM_EXTENDED_KEY_USAGE_EXT_HPP
