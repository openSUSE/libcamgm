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

  File:       ExtensionBase.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_EXTENSION_BASE_HPP
#define    LIMAL_CA_MGM_EXTENSION_BASE_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include <limal/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class CA;
	class ExtensionBaseImpl;
	
	class ExtensionBase {

	public:
		ExtensionBase(bool extPresent = false, bool extCritical = false);

		ExtensionBase(const ExtensionBase& extension);

		virtual ~ExtensionBase();

#ifndef SWIG

		ExtensionBase& operator=(const ExtensionBase& extension);

#endif
		
		void   setPresent(bool extPresent);
		void   setCritical(bool extCritical);

		bool   isCritical() const;
		bool   isPresent() const;

		virtual void commit2Config(CA& ca, Type type) const = 0;

		virtual bool                 valid() const =0;
		virtual std::vector<std::string>  verify() const =0;

		virtual std::vector<std::string>  dump() const;

	private:
		ca_mgm::RWCOW_pointer<ExtensionBaseImpl> m_impl;
	};

}

#endif // LIMAL_CA_MGM_EXTENSION_BASE_HPP
