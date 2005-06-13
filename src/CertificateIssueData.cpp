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

  File:       CertificateIssueData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CertificateIssueData.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateIssueData::CertificateIssueData()
{
}

CertificateIssueData::CertificateIssueData(CA& ca, Type type)
{
}

CertificateIssueData::CertificateIssueData(const CertificateIssueData& data)
{
}

CertificateIssueData::~CertificateIssueData()
{
}

CertificateIssueData&
CertificateIssueData::operator=(const CertificateIssueData& data)
{
    return *this;
}

void
CertificateIssueData::setCertifiyPeriode(time_t start, time_t end)
{
    notBefore = start;
    notAfter  = end;
}

time_t
CertificateIssueData::getStartDate() const
{
    return notBefore;
}

time_t
CertificateIssueData::getEndDate() const
{
    return notAfter;
}

void
CertificateIssueData::setExtensions(const X509v3CertificateIssueExtensions& ext)
{
    extensions = ext;
}

X509v3CertificateIssueExtensions
CertificateIssueData::getExtensions() const
{
    return extensions;
}

void
CertificateIssueData::commit2Config(CA& ca, Type type)
{
}


