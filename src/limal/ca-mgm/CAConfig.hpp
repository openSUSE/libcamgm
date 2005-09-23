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

  File:       CAConfig.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

/**
 * @file   CAConfig.hpp
 * @brief  This is a short description of the library.
 */
#ifndef    LIMAL_CA_CONFIG_HPP
#define    LIMAL_CA_CONFIG_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/INIParser.hpp>


namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{
    /**
     * Class for reading and writing the openssl.cnf
     */
    class CAConfig {
    public:

        /**
         * Create a new object from <b>file</b>
         */
        CAConfig(const String &file);
        ~CAConfig();

        /**
         * Set a new value in Section <b>section</b> with the Key <b>key</b>.
         */
        void     setValue(const String &section, const String &key, const String &value);

        /**
         * Delete the Key <b>key</b> in Section <b>section</b>
         */
        void     deleteValue(const String &section, const String &key);

        /**
         * Get the value of Section  <b>section</b> with the Key <b>key</b>.
         */
        String   getValue(const String &section, const String &key) const;

        /**
         * Check if Key <b>key</b> in Section <b>section</b> exists.
         */
        bool     exists(const String &section, const String &key) const;

        /**
         * Return a List of all Keys in Section <b>section</b>.
         */
        blocxx::List<blocxx::String> getKeylist(const String &section) const;

        /**
         * Copy all Keys and values from Section <b>srcSection</b> to
         * Section <b>destSection</b>.
         */
        void     copySection(const String &srcSection, const String &destSection);

        /**
         * Clone this object
         *
         * @param file a new filename for this object
         */
        CAConfig *clone(const String &file);

        void	 dump();


    private:
        INI::INIParser 	*parser;
        String		srcFilename;
        
        CAConfig();
        CAConfig(const CAConfig&);
        CAConfig& operator=(const CAConfig&);
        
        void dumpTree(INI::Section *section, int level = 0);
        
    };
    
}
}

#endif  //LIMAL_CA_CONFIG_HPP
