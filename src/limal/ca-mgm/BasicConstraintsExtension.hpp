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

  File:       BasicConstraintsExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
#define    LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    /**
     * If the ca parameter is set to true this certificate
     * is a Certificate Authority.
     * The pathlen parameter indicates the maximum number of CAs that can appear
     * below this one in a chain.
     */
    class BasicConstraintsExtension : public ExtensionBase {
    public:
        BasicConstraintsExtension();
        BasicConstraintsExtension(CAConfig* caConfig, Type type);
        BasicConstraintsExtension(bool isCa, blocxx::Int32 pathLength=-1);
        BasicConstraintsExtension(const BasicConstraintsExtension& extension);
        virtual ~BasicConstraintsExtension();

        BasicConstraintsExtension& operator=(const BasicConstraintsExtension& extension);

        /**
         * Set the ca parameter and the path length.
         *
         * @param isCA set it to true if you want a CA, otherwise false.
         * @param pathLength maximum number of CAs that can appear below this one in a chain;
         * -1 means no path Length is set.
         */
        void           setBasicConstraints(bool isCa, blocxx::Int32 pathLength=-1);

        /**
         * Return the ca parameter
         */
        bool           isCA() const;

        /**
         * Return the path length (-1 means no path length set)
         */
        blocxx::Int32  getPathLength() const;

        /**
         * Write the informations of this object back to the configuration file
         *
         * @param ca the CA object which holds the config object
         * @param type the type describes the section of the config file
         */
        virtual void commit2Config(CA& ca, Type type) const;

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
        bool           ca;
        blocxx::Int32  pathlen;
    };

}
}

#endif // LIMAL_CA_MGM_BASIC_CONSTRAINTS_EXTENSION_HPP
