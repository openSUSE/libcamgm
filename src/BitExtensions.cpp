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

  File:       BitExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/BitExtensions.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

BitExtension::BitExtension()
    : ExtensionBase()
{

}

BitExtension::BitExtension(blocxx::UInt32 value)
    : ExtensionBase()
{

}

BitExtension::BitExtension(const BitExtension& extension)
    : ExtensionBase()
{

}

BitExtension::~BitExtension()
{

}


BitExtension&
BitExtension::operator=(const BitExtension& extension)
{
    return *this;
}

void
BitExtension::setValue(blocxx::UInt32 value)
{
    this->value = value;
}

blocxx::UInt32
BitExtension::getValue() const
{
    return value;
}


// ###################################################################

       
KeyUsageExtension::KeyUsageExtension()
    : BitExtension()
{

}

KeyUsageExtension::KeyUsageExtension(CA& ca, Type type)
    : BitExtension()
{

}

KeyUsageExtension::KeyUsageExtension(blocxx::UInt32 keyUsage)
    : BitExtension()
{

}

KeyUsageExtension::KeyUsageExtension(const KeyUsageExtension& extension)
    : BitExtension()
{

}

KeyUsageExtension::~KeyUsageExtension()
{

}


KeyUsageExtension&
KeyUsageExtension::operator=(const KeyUsageExtension& extension)
{
    return *this;
}

void
KeyUsageExtension::setKeyUsage(blocxx::UInt32 keyUsage)
{
    setValue(keyUsage);
}

blocxx::UInt32
KeyUsageExtension::getKeyUsage() const
{
    return getValue();
}

bool
KeyUsageExtension::isEnabledFor(KeyUsage ku) const
{
    return false;
}

void
KeyUsageExtension::commit2Config(CA& ca, Type type)
{
}


// ###################################################################

        
NsCertTypeExtension::NsCertTypeExtension()
    : BitExtension()
{

}

NsCertTypeExtension::NsCertTypeExtension(CA& ca, Type type)
    : BitExtension()
{

}

NsCertTypeExtension::NsCertTypeExtension(blocxx::UInt32 nsCertTypes)
    : BitExtension()
{

}

NsCertTypeExtension::NsCertTypeExtension(const NsCertTypeExtension& extension)
    : BitExtension()
{

}

NsCertTypeExtension::~NsCertTypeExtension()
{

}


NsCertTypeExtension&
NsCertTypeExtension::operator=(const NsCertTypeExtension& extension)
{
    return *this;
}

void
NsCertTypeExtension::setNsCertType(blocxx::UInt32 nsCertTypes)
{
    setValue(nsCertTypes);
}

blocxx::UInt32
NsCertTypeExtension::getNsCertType() const
{
    return getValue();
}

bool
NsCertTypeExtension::isEnabledFor(NsCertType nsCertType) const
{
    return false;
}

void
NsCertTypeExtension::commit2Config(CA& ca, Type type)
{
}


// ###################################################################


ExtendedKeyUsageExtension::ExtendedKeyUsageExtension()
    : BitExtension()
{

}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(CA& ca, Type type)
    : BitExtension()
{

}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(blocxx::UInt32 extKeyUsages, 
                                                     const StringList& additionalOIDs)
    : BitExtension()
{

}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(const ExtendedKeyUsageExtension& extension)
    : BitExtension()
{

}

ExtendedKeyUsageExtension::~ExtendedKeyUsageExtension()
{

}


ExtendedKeyUsageExtension&
ExtendedKeyUsageExtension::operator=(const ExtendedKeyUsageExtension& extension)
{
    return *this;
}

void
ExtendedKeyUsageExtension::setExtendedKeyUsage(blocxx::UInt32 extKeyUsages)
{
    setValue(extKeyUsages);
}

blocxx::UInt32
ExtendedKeyUsageExtension::getExtendedKeyUsage() const
{
    return getValue();
}
        
bool
ExtendedKeyUsageExtension::isEnabledFor(ExtendedKeyUsage extKeyUsage) const
{
    return false;
}

void
ExtendedKeyUsageExtension::setAdditionalOIDs(const StringList& additionalOIDs)
{
    oids = additionalOIDs;
}

StringList
ExtendedKeyUsageExtension::getAdditionalOIDs() const
{
    return oids;
}

void
ExtendedKeyUsageExtension::addAdditionalOID(String oid)
{
    
}

bool
ExtendedKeyUsageExtension::deleteAdditionalOID(String oid)
{
    return false;
}

void
ExtendedKeyUsageExtension::commit2Config(CA& ca, Type type)
{
}

