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
    class CAConfig {
    public:
        CAConfig(const String &file);
        ~CAConfig();

        void     setValue(const String &section, const String &key, const String &value);

        void     deleteValue(const String &section, const String &key);

        String   getValue(const String &section, const String &key) const;

        bool     exists(const String &section, const String &key) const;

        List<String> CAConfig::getKeylist(const String &section) const;

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
