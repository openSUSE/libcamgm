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

  File:       StringExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/StringExtensions.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;
    
        
StringExtension::~StringExtension()
{
}

        
//    protected:

StringExtension::StringExtension(const String &v ) 
    : ExtensionBase(), value(v) 
{
}

StringExtension::StringExtension(const StringExtension& extension)
    : ExtensionBase(extension) 
{
}
        
StringExtension&
StringExtension::operator=(const StringExtension& extension)
{
    return *this;
}
        
//    private:
        
StringExtension::StringExtension()
    : ExtensionBase() 
{
}


// #################################################################

NsBaseUrlExtension::NsBaseUrlExtension(const String &v)
    : StringExtension(v)
{
}

NsBaseUrlExtension::NsBaseUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsBaseUrlExtension::NsBaseUrlExtension(const NsBaseUrlExtension &extension)
    : StringExtension(extension)
{
}

NsBaseUrlExtension::~NsBaseUrlExtension()
{
}

NsBaseUrlExtension&
NsBaseUrlExtension::operator=(const NsBaseUrlExtension& extension)
{
    return *this;
}

void
NsBaseUrlExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsBaseUrlExtension::getValue() const
{
    return value;
}

void
NsBaseUrlExtension::commit2Config(CA& ca, Type type)
{
}

// private:
NsBaseUrlExtension::NsBaseUrlExtension()
    : StringExtension(String())
{
}


// #################################################################

NsRevocationUrlExtension::NsRevocationUrlExtension(const String &v)
    : StringExtension(v)
{
}

NsRevocationUrlExtension::NsRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsRevocationUrlExtension::NsRevocationUrlExtension(const NsRevocationUrlExtension &extension)
    : StringExtension(extension)
{
}

NsRevocationUrlExtension::~NsRevocationUrlExtension()
{
}

NsRevocationUrlExtension&
NsRevocationUrlExtension::operator=(const NsRevocationUrlExtension& extension)
{
    return *this;
}

void
NsRevocationUrlExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsRevocationUrlExtension::getValue() const
{
    return value;
}

void
NsRevocationUrlExtension::commit2Config(CA& ca, Type type)
{
}

//    private:
NsRevocationUrlExtension::NsRevocationUrlExtension()
    : StringExtension(String())
{
}


// #################################################################

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(const String &v)
    : StringExtension(v)
{
}

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(const NsCaRevocationUrlExtension &extension)
    : StringExtension(extension)
{
}

NsCaRevocationUrlExtension::~NsCaRevocationUrlExtension()
{
}

NsCaRevocationUrlExtension&
NsCaRevocationUrlExtension::operator=(const NsCaRevocationUrlExtension& extension)
{
    return *this;
}

void
NsCaRevocationUrlExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsCaRevocationUrlExtension::getValue() const
{
    return value;
}

void
NsCaRevocationUrlExtension::commit2Config(CA& ca, Type type)
{
}

//  private:
NsCaRevocationUrlExtension::NsCaRevocationUrlExtension()
    : StringExtension(String())
{
}


// #################################################################

NsRenewalUrlExtension::NsRenewalUrlExtension(const String &v)
    : StringExtension(v)
{
}

NsRenewalUrlExtension::NsRenewalUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsRenewalUrlExtension::NsRenewalUrlExtension(const NsRenewalUrlExtension &extension)
    : StringExtension(extension)
{
}

NsRenewalUrlExtension::~NsRenewalUrlExtension()
{
}

NsRenewalUrlExtension&
NsRenewalUrlExtension::operator=(const NsRenewalUrlExtension& extension)
{
    return *this;
}

void
NsRenewalUrlExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsRenewalUrlExtension::getValue() const
{
    return value;
}

void
NsRenewalUrlExtension::commit2Config(CA& ca, Type type)
{
    
}

//    private:
NsRenewalUrlExtension::NsRenewalUrlExtension()
    : StringExtension(String())
{
}

// #################################################################

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(const String &v)
    : StringExtension(v)
{
}

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(const NsCaPolicyUrlExtension &extension)
    : StringExtension(extension)
{
}

NsCaPolicyUrlExtension::~NsCaPolicyUrlExtension()
{
}

NsCaPolicyUrlExtension&
NsCaPolicyUrlExtension::operator=(const NsCaPolicyUrlExtension& extension)
{
    return *this;
}

void
NsCaPolicyUrlExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsCaPolicyUrlExtension::getValue() const
{
    return value;
}

void
NsCaPolicyUrlExtension::commit2Config(CA& ca, Type type)
{
}

//    private:
NsCaPolicyUrlExtension::NsCaPolicyUrlExtension()
    : StringExtension(String())
{
}


// #################################################################

NsSslServerNameExtension::NsSslServerNameExtension(const String &v)
    : StringExtension(v)
{
}

NsSslServerNameExtension::NsSslServerNameExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsSslServerNameExtension::NsSslServerNameExtension(const NsSslServerNameExtension &extension)
    : StringExtension(extension)
{
}

NsSslServerNameExtension::~NsSslServerNameExtension()
{
}

NsSslServerNameExtension&
NsSslServerNameExtension::operator=(const NsSslServerNameExtension& extension)
{
    return *this;
}

void
NsSslServerNameExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsSslServerNameExtension::getValue() const
{
    return value;
}

void
NsSslServerNameExtension::commit2Config(CA& ca, Type type)
{
}

//    private:

NsSslServerNameExtension::NsSslServerNameExtension()
    : StringExtension(String())
{
}

// #################################################################

NsCommentExtension::NsCommentExtension(const String &v)
    : StringExtension(v)
{
}

NsCommentExtension::NsCommentExtension(CA& ca, Type type)
    : StringExtension(String())
{
}

NsCommentExtension::NsCommentExtension(const NsCommentExtension &extension)
    : StringExtension(extension)
{
}

NsCommentExtension::~NsCommentExtension()
{
}

NsCommentExtension&
NsCommentExtension::operator=(const NsCommentExtension& extension)
{
    return *this;
}

void
NsCommentExtension::setValue(const String &v)
{
    value = v;
}

blocxx::String
NsCommentExtension::getValue() const
{
    return value;
}

void
NsCommentExtension::commit2Config(CA& ca, Type type)
{
}

//    private:
NsCommentExtension::NsCommentExtension()
    : StringExtension(String())
{
}
