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

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include <ca-mgm/PtrTypes.hpp>


namespace CA_MGM_NAMESPACE
{

	class CAConfigImpl;

	/**
     * Class for reading and writing the openssl.cnf
     */
	class CAConfig
	{
	public:

		/**
		 * Create a new object from <b>file</b>
		 */
		CAConfig(const std::string &file);
		~CAConfig();

		/**
		 * Set a new value in Section <b>section</b> with the Key <b>key</b>.
		 */
		void
		setValue(const std::string &section, const std::string &key, const std::string &value);

		/**
		 * Delete the Key <b>key</b> in Section <b>section</b>
		 */
		void
		deleteValue(const std::string &section, const std::string &key);

        void
        deleteSection(const std::string &section);

		/**
		 * Get the value of Section  <b>section</b> with the Key <b>key</b>.
		 */
		std::string
		getValue(const std::string &section, const std::string &key) const;

		/**
		 * Check if Key <b>key</b> in Section <b>section</b> exists.
		 */
		bool
		exists(const std::string &section, const std::string &key) const;

		/**
		 * Return a List of all Keys in Section <b>section</b>.
		 */
		std::list<std::string>
		getKeylist(const std::string &section) const;

		/**
		 * Copy all Keys and values from Section <b>srcSection</b> to
		 * Section <b>destSection</b>.
		 */
		void
		copySection(const std::string &srcSection, const std::string &destSection);

		/**
		 * Clone this object
		 *
		 * @param file a new filename for this object
		 */
		CAConfig*
		clone(const std::string &file);

		/**
		 * return current filename
		 */
		std::string
		filename() const;

		void	 dump();


	private:
		ca_mgm::RWCOW_pointer<CAConfigImpl> m_impl;

		CAConfig();
		CAConfig(const CAConfig&);
		CAConfig& operator=(const CAConfig&);

		class CASection;
		void dumpTree(CASection *section, int level = 0);

		/**
		 * Check the format of the template and fix it if required.
		 * (SLES9 => SLES10 update)
		 */
		void validateAndFix();
	};

}

#endif  //LIMAL_CA_CONFIG_HPP
