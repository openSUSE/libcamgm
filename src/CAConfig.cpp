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

  File:       CAConfig.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/CAConfig.hpp>
// #include  <limal/INIBase.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CAConfig::CAConfig(const String &file)
{

}

CAConfig::~CAConfig()
{
}

void
CAConfig::setValue(const String &section, const String &key, const String &value)
{
}

void
CAConfig::deleteValue(const String &section, const String &key)
{
}

blocxx::String
CAConfig::getValue(const String &section, const String &key) const
{
    return String();
}

CAConfig
CAConfig::clone(const String &file)
{
    return CAConfig();
}

// private

CAConfig::CAConfig()
{
}

CAConfig::CAConfig(const CAConfig&)
{
}

CAConfig&
CAConfig::operator=(const CAConfig&)
{
    return *this;
}


