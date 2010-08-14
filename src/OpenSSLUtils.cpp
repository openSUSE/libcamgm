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

  File:       OpenSSLUtils.cpp

  Author:     Michael Calmer
  Maintainer: Michael Calmer
/-*/

#include "OpenSSLUtils.hpp"

#include <limal/Exception.hpp>
#include <limal/PathUtils.hpp>
#include <limal/PathInfo.hpp>
#include <limal/PathName.hpp>
#include <limal/ca-mgm/LocalManagement.hpp>
#include <limal/PerlRegEx.hpp>
#include <limal/String.hpp>
#include <limal/Date.hpp>
#include <fstream>
#include "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

OpenSSLUtils::OpenSSLUtils(const std::string &configFile,
                           const std::string &command,
                           const std::string &tmpDir)
	: m_cmd(command), m_tmp(tmpDir), m_conf(configFile)
{
	path::PathInfo pi(configFile);

	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("File does not exist: " << configFile);
		CA_MGM_THROW_ERR(ca_mgm::ValueException,
		                 str::form(__("File does not exist: %s."), configFile.c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(tmpDir);
	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR("Directory does not exist: " << tmpDir);
		CA_MGM_THROW_ERR(ca_mgm::ValueException,
		                 str::form(__("Directory does not exist: %s."), tmpDir.c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(command);
	if(!pi.exists() || !pi.isFile() || !pi.isX())
	{
		LOGIT_ERROR("Invalid command: " << command);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid command %s."), command.c_str()).c_str());
	}

	path::PathName r = path::PathName::dirName(configFile);
	if( r.toString() == "")
	{
		m_rand = "./.rand";
	}
	else
	{
		m_rand = r.toString() + "/.rand";
	}
}

void
OpenSSLUtils::createRSAKey(const std::string &outFile,
                           const std::string &password,
                           uint32_t     bits,
                           const std::string &cryptAlgorithm)
{
	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "genrsa ";
	debugCmd += "-out ";
	debugCmd += outFile + " ";

	if(!cryptAlgorithm.empty())
	{
		debugCmd += "-passout env:pass ";
		debugCmd += "-" + cryptAlgorithm + " ";
	}

	debugCmd += str::numstring(bits);

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	Environment env;
	env["PATH"] = "/usr/bin/";
	env["RANDFILE"] = m_rand.c_str();
	env["pass"] = password.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");
		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::createRequest(const std::string &outFile,
                            const std::string &keyFile,
                            const std::string &password,
                            const std::string &extension,
                            FormatType         outForm)
{
	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "req -new -batch ";

	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	if(!extension.empty())
	{
		debugCmd += "-reqexts " + extension + " ";
	}

	debugCmd += "-key " + keyFile + " ";

	if(outForm == E_PEM)
	{
		debugCmd += "-outform PEM ";
	}
	else
	{
		debugCmd += "-outform DER ";
	}

	debugCmd += "-out " + outFile + " ";

	debugCmd += "-passin env:pass ";

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = password.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::createSelfSignedCertificate(const std::string &outFile,
                                          const std::string &keyFile,
                                          const std::string &requestFile,
                                          const std::string &password,
                                          const std::string &extension,
                                          uint32_t     days,
                                          bool          noEmailDN)
{
	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(requestFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid request file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid request file specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "req -x509 ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	if(noEmailDN)
	{
		debugCmd += "-noemailDN ";
	}

	debugCmd += "-passin env:pass ";

	if(!extension.empty())
	{
		debugCmd += "-extensions " + extension + " ";
	}

	debugCmd += "-days " + str::numstring(days) + " ";

	debugCmd += "-in "  + requestFile + " ";
	debugCmd += "-key " + keyFile + " ";
	debugCmd += "-out " + outFile + " ";

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = password.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::signRequest(const std::string &requestFile,
                          const std::string &outFile,
                          const std::string &caKeyFile,
                          const std::string &caPassword,
                          const std::string &extension,
                          const std::string &startDate,
                          const std::string &endDate,
                          const std::string &caSection,
                          const std::string &outDir,
                          bool          noEmailDN,
                          bool          noUniqueDN,
                          bool          noText)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(requestFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid request file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid request file specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -batch ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-passin env:pass ";

	if(!caSection.empty())
	{
		debugCmd += "-name "  + caSection   + " ";
	}

	if(!extension.empty())
	{
		debugCmd += "-extensions " + extension + " ";
	}

	debugCmd += "-startdate " + startDate + " ";
	debugCmd += "-enddate "   + endDate   + " ";

	if(noEmailDN)
	{
		debugCmd += "-noemailDN ";
	}
	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}
	if(noText)
	{
		debugCmd += "-notext ";
	}

	debugCmd += "-in "  + requestFile + " ";
	debugCmd += "-out " + outFile + " ";

	if(!outDir.empty())
	{
		debugCmd += "-outdir " + outDir + " ";
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);
	//LOGIT_DEBUG("PASSWORD: " << caPassword);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = caPassword.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::revokeCertificate(const std::string &caCertFile,
                                const std::string &caKeyFile,
                                const std::string &caPassword,
                                const std::string &certFile,
                                const CRLReason      &reason,
                                bool                  noUniqueDN)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	pi.stat(certFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid certificate file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid certificate file specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-revoke " + certFile + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}

	if(0 != str::compareCI(reason.getReason(), "none"))
	{
		std::string reasonStr = reason.getReason();

		if(0 == str::compareCI(reasonStr, "certificateHold"))
		{
			debugCmd += "-crl_hold " + reason.getHoldInstruction() + " ";
		}
		else if(0 == str::compareCI(reasonStr, "keyCompromise"))
		{
			if(reason.getKeyCompromiseDateAsString() == "")
			{
				debugCmd += "-crl_reason keyCompromise ";
			}
			else
			{
				debugCmd += "-crl_compromise " +
					reason.getKeyCompromiseDateAsString() + " ";
			}
		}
		else if(0 == str::compareCI(reasonStr, "CACompromise"))
		{
			if(reason.getCACompromiseDateAsString() == "")
			{
				debugCmd += "-crl_reason CACompromise ";
			}
			else
			{
				debugCmd += "-crl_CA_compromise " +
					reason.getCACompromiseDateAsString() + " ";
			}
		}
		else
		{
			debugCmd += "-crl_reason " + reasonStr + " ";
		}
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = caPassword.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::issueCRL(const std::string &caCertFile,
                       const std::string &caKeyFile,
                       const std::string &caPassword,
                       uint32_t        hours,
                       const std::string &outfile,
                       const std::string &extension,
                       bool                  noUniqueDN)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -gencrl ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-out " + outfile + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	debugCmd += "-crlhours " + str::numstring(hours) + " ";

	if(!extension.empty())
	{
		debugCmd += "-crlexts " + extension + " ";
	}

	if(noUniqueDN)
	{
		debugCmd += "-nouniqueDN ";
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = caPassword.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

void
OpenSSLUtils::updateDB(const std::string &caCertFile,
                       const std::string &caKeyFile,
                       const std::string &caPassword)
{
	path::PathInfo pi(caKeyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid keyfile specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid key file specified."));
	}

	pi.stat(caCertFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid CA certificate file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid CA certificate file specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca -updatedb ";

	debugCmd += "-config ";
	debugCmd += m_conf + " ";

	debugCmd += "-keyfile " + caKeyFile + " ";

	debugCmd += "-cert " + caCertFile + " ";

	debugCmd += "-passin env:pass ";

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["pass"] = caPassword.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	PerlRegEx r("error");

	if( (status != 0 && status != 256) || r.match(errOutput) )
	{
		LOGIT_ERROR("openssl status:" << str::numstring(status));
		LOGIT_ERROR("openssl stderr:" << errOutput);
		LOGIT_DEBUG("openssl stdout:" << stdOutput);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	if(!errOutput.empty())
	{
		LOGIT_DEBUG("openssl stderr:" << errOutput);
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}
}

std::string
OpenSSLUtils::verify(const std::string &certFile,
                     const std::string &caPath,
                     bool                  crlCheck,
                     const std::string &purpose)
{
	path::PathInfo pi(certFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("No valid certificate file specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid certificate file specified."));
	}

	pi.stat(caPath);
	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR("No valid CA directory specified");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("No valid CA directory specified."));
	}

	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "verify ";

	debugCmd += "-CApath " + caPath + " ";

	if(!purpose.empty())
	{
		debugCmd += "-purpose " + purpose + " ";
	}

	if(crlCheck)
	{
		debugCmd += "-crl_check_all ";
	}

	debugCmd += certFile;

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	std::vector<std::string> lines = PerlRegEx("\n").split(stdOutput);
	std::vector<std::string>::const_iterator line;

	std::string result;
	std::string errMsg;
	std::string errNum;
	PerlRegEx ok("\\.pem:\\s+(.*)\\s*$");
	PerlRegEx error("^error\\s+(\\d+)\\s+at\\s+\\d+\\s+[\\w\\s]+:(.*)$");

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		std::vector<std::string> sa = ok.capture(*line);

		if(sa.size() == 2 && sa[1] == "OK")
		{
			result = "OK";
			break;
		}

		sa = error.capture(*line);

		if(sa.size() == 3)
		{
			result = sa[2];
			errMsg = *line;
			errNum = sa[1];
		}
	}

	if(result != "OK")
	{
		if(!errOutput.empty())
		{
			LOGIT_INFO(str::form("Certificate invalid! (%s / %s)", result.c_str(), errMsg.c_str()));
			LOGIT_ERROR("openssl stderr:" << errOutput);
		}

		return str::form("Certificate invalid! (%s / %s)", result.c_str(), errMsg.c_str());
	}
	else
	{
		return "";
	}
}

std::string
OpenSSLUtils::status(const std::string &serial)
{
	std::string debugCmd;

	debugCmd += m_cmd + " ";
	debugCmd += "ca ";

	debugCmd += "-config " + m_conf + " ";

	debugCmd += "-status " + serial;

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}

	std::vector<std::string> lines = PerlRegEx("\n").split(errOutput);
	std::vector<std::string>::const_iterator line;

	std::string errMsg;

	PerlRegEx serialMatch(serial + "=(\\w+)\\s+.*$");

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		std::vector<std::string> sa = serialMatch.capture(*line);

		if(sa.size() == 2)
		{
			return sa[1];
		}
		else
		{
			errMsg += *line + "\n";
		}
	}
	LOGIT_ERROR(str::form("Show certificate status with serial '%s' failed.(%d)",
	                   serial.c_str(), status));
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
	}
	CA_MGM_THROW(ca_mgm::RuntimeException,
	             str::form(__("Showing certificate status with serial %s failed (%d)."),
	                    serial.c_str(), status).c_str());
}

bool
OpenSSLUtils::checkKey(const std::string &caName,
                       const std::string &password,
                       const std::string &certificateName,
                       const std::string &repository)
{
	std::string keyFile;

	if(certificateName == "cacert")
	{
		keyFile = repository + "/" + caName + "/cacert.key";
	}
	else
	{
		PerlRegEx r("^[[:xdigit:]]+:([[:xdigit:]]+[\\d-]*)$");
		std::vector<std::string> sa = r.capture(certificateName);

		if(sa.size() != 2)
		{
			LOGIT_ERROR("Can not parse certificate name");
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             __("Cannot parse the certificate name."));
		}

		keyFile = repository + "/" + caName + "/keys/" + sa[1] + ".key";
	}

	path::PathInfo pi(keyFile);
	if(!pi.exists() || !pi.isFile())
	{
		LOGIT_ERROR("Keyfile does not exist");
		CA_MGM_THROW(ca_mgm::SystemException,
		             __("The key file does not exist."));
	}

	std::string debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "rsa -noout -in ";
	debugCmd += keyFile + " ";
	debugCmd += "-passin env:PASSWORD ";

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = m_rand.c_str();
    env["PASSWORD"] = password.c_str();

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// ###################################################
// ### static functions
// ###################################################


ca_mgm::ByteBuffer
OpenSSLUtils::x509Convert(const ByteBuffer &certificate,
                          FormatType inform,
                          FormatType outform )
{
	// FIXME: use tmp file
	std::string inFileName(::tempnam("/tmp/", "x509I"));
	std::string outFileName(::tempnam("/tmp/", "x509O"));

	LocalManagement::writeFile(certificate, inFileName,
	                           false, 0600);

	std::string debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "x509 ";
	debugCmd += "-nameopt ";
	debugCmd += "RFC2253 ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

    std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();
	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::rsaConvert(const ByteBuffer &key,
                         FormatType inform,
                         FormatType outform,
                         const std::string &inPassword,
                         const std::string &outPassword,
                         const std::string &algorithm)
{
	// FIXME: use tmp file
	std::string inFileName(::tempnam("/tmp/", "keyIn"));
	std::string outFileName(::tempnam("/tmp/", "keyOt"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(key, inFileName,
	                           false, 0600);

	std::string debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "rsa ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	if(!inPassword.empty() && inform != E_DER)
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}

	if(!outPassword.empty() && outform != E_DER)
	{
		debugCmd += "-passout env:outpass ";

		debugCmd += "-"+ algorithm;
		isOutPassSet = true;
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();

	if(isInPassSet)
	{
		env["inpass"] = inPassword.c_str();
	}

	if(isOutPassSet)
	{
		env["outpass"] = outPassword.c_str();
	}

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		// This message is not an error
		if(!PerlRegEx("^writing RSA key$", PCRE_CASELESS).match(errOutput))
		{
			LOGIT_ERROR("openssl stderr:" << errOutput);
			foundError = true;
		}
		else
		{
			LOGIT_DEBUG("openssl stderr:" << errOutput);
		}
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("unable to load Private Key", PCRE_CASELESS).match(msg))
		{
			CA_MGM_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             str::form(__("openssl command failed: %s"),msg.c_str()).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::crlConvert(const ByteBuffer &crl,
                         FormatType inform,
                         FormatType outform )
{
	// FIXME: use tmp file
	std::string inFileName(::tempnam("/tmp/", "crlIn"));
	std::string outFileName(::tempnam("/tmp/", "crlOt"));

	LocalManagement::writeFile(crl, inFileName,
	                           false, 0600);

	std::string debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "crl ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();
	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::reqConvert(const ByteBuffer &req,
                         FormatType inform,
                         FormatType outform )
{
	// FIXME: use tmp file
	std::string inFileName(::tempnam("/tmp/", "reqIn"));
	std::string outFileName(::tempnam("/tmp/", "reqOt"));

	LocalManagement::writeFile(req, inFileName,
	                           false, 0600);

	std::string debugCmd;
	bool foundError = false;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "req ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";
	debugCmd += "-inform ";

	switch(inform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	debugCmd += "-outform ";

	switch(outform)
	{
	case E_PEM:
		debugCmd += "PEM ";
		break;
	case E_DER:
		debugCmd += "DER ";
		break;
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();
	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::createPKCS12(const ByteBuffer &certificate,
                           const ByteBuffer &key,
                           const std::string     &inPassword,
                           const std::string     &outPassword,
                           const ByteBuffer &caCert,
                           const std::string     &caPath,
                           bool              withChain )
{
	// FIXME: use tmp file
	std::string inFileName1(::tempnam("/tmp/", "crtIn"));
	std::string inFileName2(::tempnam("/tmp/", "keyIn"));
	std::string inFileName3(::tempnam("/tmp/", "caIn"));
	std::string outFileName(::tempnam("/tmp/", "p12Ot"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(certificate, inFileName1,
	                           false, 0600);
	LocalManagement::writeFile(key, inFileName2,
	                           false, 0600);
	if(!caCert.empty())
	{
		LocalManagement::writeFile(caCert, inFileName3,
		                           false, 0600);
	}

	std::string debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "pkcs12 ";
	debugCmd += "-in ";
	debugCmd += inFileName1 + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";

	debugCmd += "-export ";

	if(!caPath.empty())
	{
		debugCmd += "-CApath ";
		debugCmd += caPath + " ";

		if( withChain )
		{
			debugCmd += "-chain ";
		}
	}

	if(!inPassword.empty())
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}

	if(!outPassword.empty())
	{
		debugCmd += "-passout env:outpass ";
		isOutPassSet = true;
	}
	else
	{
		LOGIT_ERROR("Out password is required");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("The password for encrypting the output is required."));
	}

	debugCmd += "-inkey ";
	debugCmd += inFileName2 + " ";

	if(!caCert.empty())
	{
		debugCmd += "-certfile ";
		debugCmd += inFileName3 + " ";
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();

	if(isInPassSet)
	{
		env["inpass"] = inPassword.c_str();
	}

	if(isOutPassSet)
	{
		env["outpass"] = outPassword.c_str();
	}

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName1);
		path::removeFile(inFileName2);
		if(!caCert.empty())
		{
			path::removeFile(inFileName3);
		}
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		LOGIT_ERROR("openssl stderr:" << errOutput);
		foundError = true;
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName1);
		path::removeFile(inFileName2);
		if(!caCert.empty())
		{
			path::removeFile(inFileName3);
		}
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("unable to load Private Key", PCRE_CASELESS).match(msg))
		{
			CA_MGM_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName1);
	path::removeFile(inFileName2);
	if(!caCert.empty())
	{
		path::removeFile(inFileName3);
	}
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

ca_mgm::ByteBuffer
OpenSSLUtils::pkcs12ToPEM(const ByteBuffer &pkcs12,
                          const std::string     &inPassword,
                          const std::string     &outPassword,
                          const std::string     &algorithm)
{
	// FIXME: use tmp file
	std::string inFileName(::tempnam("/tmp/", "p12In"));
	std::string outFileName(::tempnam("/tmp/", "x509O"));

	bool isInPassSet = false;
	bool isOutPassSet = false;
	bool foundError = false;

	LocalManagement::writeFile(pkcs12, inFileName,
	                           false, 0600);

	std::string debugCmd;

	debugCmd += ca_mgm::OPENSSL_COMMAND + " ";
	debugCmd += "pkcs12 ";
	debugCmd += "-in ";
	debugCmd += inFileName + " ";
	debugCmd += "-out ";
	debugCmd += outFileName + " ";

	// -nokeys?

	if(!inPassword.empty())
	{
		debugCmd += "-passin env:inpass ";
		isInPassSet = true;
	}
	else
	{
		LOGIT_ERROR("PKCS12 password is required");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("The PKCS12 password is required."));
	}

	if(!outPassword.empty())
	{
		debugCmd += "-passout env:outpass ";
		debugCmd += "-" + algorithm + " ";
		isOutPassSet = true;
	}
	else
	{
		debugCmd += "-nodes ";
	}

	std::vector<std::string> cmd = PerlRegEx("\\s").split(debugCmd);

	LOGIT_DEBUG("Command: " << debugCmd);

	std::string randfile(::tempnam("/tmp/", ".rand-"));
    Environment env;
    env["PATH"] = "/usr/bin/";
    env["RANDFILE"] = randfile.c_str();

	if(isInPassSet)
	{
		env["inpass"] = inPassword.c_str();
	}

	if(isOutPassSet)
	{
		env["outpass"] = outPassword.c_str();
	}

	std::string stdOutput;
	std::string errOutput;
	int            status    = -1;

	try
	{
		status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
		                                           errOutput, env);
	}
	catch(Exception& e)
	{
		LOGIT_ERROR( "openssl exception:" << e);
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);
		CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
		                   __("Executing openssl command failed."), e);
	}
	if(status != 0)
	{
		LOGIT_INFO( "openssl status:" << str::numstring(status));
		foundError = true;
	}
	if(!errOutput.empty())
	{
		// This message is not an error
		if(!PerlRegEx("^MAC verified OK$", PCRE_CASELESS).match(errOutput))
		{
			LOGIT_ERROR("openssl stderr:" << errOutput);
			foundError = true;
		}
		else
		{
			LOGIT_DEBUG("openssl stderr:" << errOutput);
		}
	}
	if(!stdOutput.empty())
	{
		LOGIT_DEBUG("openssl stdout:" << stdOutput);
	}

	if(foundError)
	{
		path::removeFile(inFileName);
		path::removeFile(outFileName);
		path::removeFile(randfile);

		std::vector<std::string> sa;
        str::split(errOutput, std::back_inserter(sa), "\n\r");

		std::string msg = (sa.empty()? "" : sa[0]);
		if(PerlRegEx("invalid password", PCRE_CASELESS).match(msg))
		{
			CA_MGM_THROW_ERR(ca_mgm::ValueException,
			                 __("Invalid password."), E_INVALID_PASSWD);
		}
		else
		{
			CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("openssl command failed: %s"), msg.c_str()).c_str());
		}
	}

	ByteBuffer out = LocalManagement::readFile(outFileName);

	path::removeFile(inFileName);
	path::removeFile(outFileName);
	path::removeFile(randfile);

	return out;
}

std::vector<std::string>
OpenSSLUtils::listCA(const std::string &repository)
{
	std::list<std::string>  tmpList;
	std::vector<std::string> retList;

	int r = path::readDir(tmpList, repository, false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << repository <<
		            "(" << ::strerror(r) << ") [" << r << "]");
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot read directory: %s (%s) [%d]."),
		                    repository.c_str(), ::strerror(r), r).c_str());
	}

	tmpList.sort();

	std::list<std::string>::const_iterator cont;

	path::PathInfo pi(repository);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(repository + "/" + *cont);

		if(pi.exists() && pi.isDir())
		{
			pi.stat(repository + "/" + *cont + "/openssl.cnf.tmpl");

			if(pi.exists() && pi.isFile())
			{
				pi.stat(repository + "/" + *cont + "/cacert.pem");

				if(pi.exists() && pi.isFile())
				{
					retList.push_back(*cont);
				}
			}
		}
	}
	return retList;
}

std::string
OpenSSLUtils::nextSerial(const std::string &serialFile)
{
	ByteBuffer b = LocalManagement::readFile(serialFile);

	std::string s(b.data(), b.size());
	PerlRegEx r("^([[:xdigit:]]+)$");

	std::vector<std::string> sa = r.capture(s);

	if(sa.size() == 2)
	{
		return sa[1];
	}
	else
	{
		LOGIT_ERROR("No serial number found in " << serialFile);
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("No serial number found in %s."),
		                    serialFile.c_str()).c_str());
	}
}

void
OpenSSLUtils::addCAM(const std::string &caName,
                     const std::string &md5,
                     const std::string &dnString,
                     const std::string &repository)
{
	std::vector<std::vector<std::string> > db = OpenSSLUtils::parseCAMDB(caName, repository);
	std::vector<std::vector<std::string> >::const_iterator it;

	for(it = db.begin(); it != db.end(); ++it)
	{
		if( (*it)[0] == md5 )
		{
			LOGIT_ERROR("Request already exist.");
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             __("The request already exists."));
		}
	}

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	std::string cam(b.data(), b.size());
	cam += md5 + " " + dnString + "\n";

	LocalManagement::writeFile(ByteBuffer(cam.c_str(), cam.length()),
	                           repository + "/" + caName + "/cam.txt");

}

void
OpenSSLUtils::delCAM(const std::string &caName,
                     const std::string &md5,
                     const std::string &repository)
{
	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	std::string cam(b.data(), b.size());

	std::vector<std::string> lines = PerlRegEx("\n").split(cam);

	std::vector<std::string>::const_iterator line;
	std::string camNew;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^" + md5);

		if(!r.match(*line))
		{
			camNew += *line + "\n";
		}
	}
	LocalManagement::writeFile(ByteBuffer(camNew.c_str(), camNew.length()),
	                           repository + "/" + caName + "/cam.txt");

}

std::vector<std::vector<std::string> >
OpenSSLUtils::parseCAMDB(const std::string &caName,
                         const std::string &repository)
{
	std::vector<std::vector<std::string> > ret;

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/cam.txt");

	std::string cam(b.data(), b.size());

	std::vector<std::string> lines = PerlRegEx("\n").split(cam);

	std::vector<std::string>::const_iterator line;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^([[:xdigit:]]+[\\d-]*)\\s(.*)$");

		std::vector<std::string> col = r.capture(*line);

		if(col.size() != 3)
		{
			LOGIT_INFO("Can not parse line '" << *line << "'");
			continue;
		}

		std::vector<std::string> a;
		a.push_back(col[1]);
		a.push_back(col[2]);
		ret.push_back(a);
	}
	return ret;
}

std::vector<std::vector<std::string> >
OpenSSLUtils::parseIndexTXT(const std::string &caName,
                            const std::string &repository)
{
	std::vector<std::vector<std::string> > ret;

	ByteBuffer b = LocalManagement::readFile(repository + "/" + caName + "/index.txt");

	std::string cam(b.data(), b.size());

	std::vector<std::string> lines = PerlRegEx("\n").split(cam);

	std::vector<std::string>::const_iterator line;

	for(line = lines.begin(); line != lines.end(); ++line)
	{
		PerlRegEx r("^(\\w)\\s([\\d\\w]+)\\s([\\w\\d,.]*)\\s([[:xdigit:]]+)\\s(\\w+)\\s(.*)$");

		std::vector<std::string> col = r.capture(*line);

		if(col.size() != 7)
		{
			LOGIT_INFO("Can not parse line '" << *line << "'");
			continue;
		}

		std::vector<std::string> a;
		a.push_back(col[1]);
		a.push_back(col[2]);
		a.push_back(col[3]);
		a.push_back(col[4]);
		a.push_back(col[5]);
		a.push_back(col[6]);
		ret.push_back(a);
	}
	return ret;
}

std::vector<std::map<std::string, std::string> >
OpenSSLUtils::listRequests(const std::string &caName,
                           const std::string &repository)
{
	std::vector<std::map<std::string, std::string> > ret;
	std::list<std::string> tmpList;

	std::string reqDir = repository + "/" + caName + "/req/";

	int r = path::readDir(tmpList, reqDir , false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << reqDir <<
		            "(" << ::strerror(r) << ") [" << r << "]");
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot read directory: %s (%s) [%d]."),
		                    reqDir.c_str(), ::strerror(r), r).c_str());
	}

	tmpList.sort();

	std::vector<std::vector<std::string> >        camdb = OpenSSLUtils::parseCAMDB(caName, repository);
	std::list<std::string>::const_iterator cont;
	path::PathInfo pi(reqDir);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(reqDir + "/" + *cont);

		if(!pi.exists() || !pi.isFile())
		{
			LOGIT_INFO("skipping file " << pi.toString());
			continue;
		}

		PerlRegEx requestR("^([[:xdigit:]]+)-?(\\d*)\\.req$");

		std::vector<std::string> sa = requestR.capture(*cont);

		if(sa.size() <= 1)
		{
			LOGIT_INFO("unknown filename ... skipping (" << *cont << ")");
			continue;
		}

		std::string md5 = sa[1];
		std::string date;

        if(sa.size() == 3 && !sa[2].empty())
		{
			md5 += "-" + sa[2];

			Date dt( sa[2] );
			date = std::string(dt.form("%Y-%m-%d %H:%M:%S", false));
		}

		std::map<std::string, std::string> reqLine;
		std::string              subject;

		reqLine["request"] = md5;
		reqLine["date"]    = date;

		std::vector<std::vector<std::string> >::const_iterator dbIT;
		for(dbIT = camdb.begin(); dbIT != camdb.end(); ++dbIT)
		{
			if( (*dbIT)[0] == md5 )
			{
				subject = (*dbIT)[1];
				break;
			}
		}

		if(subject.empty())
		{
			LOGIT_ERROR("Can not find request subject.");
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             __("Cannot find the request subject."));
		}

		sa.clear();
		while(1)
		{
			std::vector<std::string> saTmp = PerlRegEx("(.*?[^\\\\])(\\/|$)").capture(subject);
			uint pos = 0;

			if(saTmp.size() >=2)
			{
				pos = saTmp[1].length();
				sa.push_back(saTmp[1]);
			}
			else
			{
				break;
			}
			subject = subject.substr(pos);
		}

		PerlRegEx cR("^C=");
		PerlRegEx stR("^ST=");
		PerlRegEx lR("^L=");
		PerlRegEx oR("^O=");
		PerlRegEx ouR("^OU=");
		PerlRegEx cnR("^CN=");
		PerlRegEx emailR("^emailAddress=");

		PerlRegEx quoteR("\\\\/");

		std::vector<std::string>::const_iterator it;
		for(it = sa.begin(); it != sa.end(); ++it)
		{
			std::string toMatch = quoteR.replace(*it, "/", true);
			toMatch = PerlRegEx("^/").replace(toMatch, "");

			if(cR.match(toMatch))
			{
				reqLine["country"]  = toMatch.substr(2);
			}
			else if(stR.match(toMatch))
			{
				reqLine["stateOrProvinceName"]  = toMatch.substr(3);
			}
			else if(lR.match(toMatch))
			{
				reqLine["localityName"]  = toMatch.substr(2);
			}
			else if(oR.match(toMatch))
			{
				reqLine["organizationName"]  = toMatch.substr(2);
			}
			else if(ouR.match(toMatch))
			{
				reqLine["organizationalUnitName"]  = toMatch.substr(3);
			}
			else if(cnR.match(toMatch))
			{
				reqLine["commonName"]  = toMatch.substr(3);
			}
			else if(emailR.match(toMatch))
			{
				reqLine["emailAddress"]  = toMatch.substr(13);
			}
			else
			{
				LOGIT_INFO("Unknown rdn: " << toMatch);
			}
		}
		ret.push_back(reqLine);
	}
	return ret;
}

std::vector<std::map<std::string, std::string> >
OpenSSLUtils::listCertificates(const std::string &caName,
                               const std::string &repository)
{
	std::vector<std::map<std::string, std::string> > ret;
	std::list<std::string> tmpList;

	std::string certDir = repository + "/" + caName + "/newcerts/";

	int r = path::readDir(tmpList, certDir , false);

	if(r != 0)
	{
		LOGIT_ERROR("Cannot read directory: " << certDir <<
		            "(" << ::strerror(r) << ") [" << r << "]");
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot read directory: %s (%s) [%d]."),
		                    certDir.c_str(), ::strerror(r), r).c_str());
	}

	tmpList.sort();

	std::vector<std::vector<std::string> >        indexTXT = OpenSSLUtils::parseIndexTXT(caName, repository);
	std::list<std::string>::const_iterator cont;
	path::PathInfo pi(certDir);

	for(cont = tmpList.begin(); cont != tmpList.end(); ++cont)
	{
		pi.stat(certDir + "/" + *cont);

		if(!pi.exists() || !pi.isFile())
		{
			LOGIT_INFO("skipping file " << pi.toString());
			continue;
		}

		PerlRegEx certR("^([[:xdigit:]]+):([[:xdigit:]]+-?\\d*)\\.pem$");

		std::vector<std::string> sa = certR.capture(*cont);

		if(sa.size() != 3)
		{
			LOGIT_INFO("unknown filename ... skipping (" << *cont << ")");
			continue;
		}

		std::string serial = sa[1];
		std::string md5    = sa[2];

		std::map<std::string, std::string> certLine;
		std::string              subject;

		certLine["serial"]      = serial;
		certLine["certificate"] = serial + ":" + md5;

		std::vector<std::vector<std::string> >::const_iterator dbIT;
		for(dbIT = indexTXT.begin(); dbIT != indexTXT.end(); ++dbIT)
		{
			if( (*dbIT)[3] == serial )
			{
				subject = (*dbIT)[5];

				if((*dbIT)[0] == "V" )
				{
					certLine["status"] = "Valid";
				}
				else if((*dbIT)[0] == "R" )
				{
					certLine["status"] = "Revoked";
				}
				else if((*dbIT)[0] == "E" )
				{
					certLine["status"] = "Expired";
				}
				else
				{
					certLine["status"] = (*dbIT)[0];
				}
				break;
			}
		}

		if(subject.empty())
		{
			LOGIT_ERROR("Can not find certificate subject.");
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             __("Cannot find the certificate subject."));
		}

		sa.clear();
		while(1)
		{
			std::vector<std::string> saTmp = PerlRegEx("(.*?[^\\\\])(\\/|$)").capture(subject);
			uint pos = 0;

			if(saTmp.size() >=2)
			{
				pos = saTmp[1].length();
				sa.push_back(saTmp[1]);
			}
			else
			{
				break;
			}
			subject = subject.substr(pos);
		}

		PerlRegEx cR("^C=");
		PerlRegEx stR("^ST=");
		PerlRegEx lR("^L=");
		PerlRegEx oR("^O=");
		PerlRegEx ouR("^OU=");
		PerlRegEx cnR("^CN=");
		PerlRegEx emailR("^emailAddress=");

		PerlRegEx quoteR("\\\\/");

		std::vector<std::string>::const_iterator it;
		std::string lastPart;
		for(it = sa.begin(); it != sa.end(); ++it)
		{
			std::string toMatch = quoteR.replace(*it, "/", true);
			toMatch = PerlRegEx("^/").replace(toMatch, "");

			if(cR.match(toMatch))
			{
				certLine["country"]  = toMatch.substr(2);
				lastPart = "country";
			}
			else if(stR.match(toMatch))
			{
				certLine["stateOrProvinceName"]  = toMatch.substr(3);
				lastPart = "stateOrProvinceName";
			}
			else if(lR.match(toMatch))
			{
				certLine["localityName"]  = toMatch.substr(2);
				lastPart = "localityName";
			}
			else if(oR.match(toMatch))
			{
				certLine["organizationName"]  = toMatch.substr(2);
				lastPart = "organizationName";
			}
			else if(ouR.match(toMatch))
			{
				certLine["organizationalUnitName"]  = toMatch.substr(3);
				lastPart = "organizationalUnitName";
			}
			else if(cnR.match(toMatch))
			{
				certLine["commonName"]  = toMatch.substr(3);
				lastPart = "commonName";
			}
			else if(emailR.match(toMatch))
			{
				certLine["emailAddress"]  = toMatch.substr(13);
				lastPart = "emailAddress";
			}
			else
			{
				if(!lastPart.empty() && (*it).at(0) == '/')
				{
					certLine[lastPart]  = certLine[lastPart] + *it;
					LOGIT_DEBUG(str::form("Append '%s' to %s", (*it).c_str(), lastPart.c_str()));
				}
				else
				{
					LOGIT_INFO("Unknown rdn: " << toMatch);
				}
			}
		}
		ret.push_back(certLine);
	}
	return ret;
}

void
OpenSSLUtils::createCaInfrastructure(const std::string &caName,
                                     const std::string &repository)
{
	if(caName.empty() || !PerlRegEx("\\w+").match(caName))
	{
		LOGIT_ERROR("Invalid caName: " << caName);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid caName: %s."), caName.c_str()).c_str());
	}

	path::PathInfo pi(repository);

	if(!pi.exists() || !pi.isDir())
	{
		LOGIT_ERROR(repository << " does not exist");
		CA_MGM_THROW_ERR(ca_mgm::SystemException,
		                 str::form(__("'%s' does not exist."), repository.c_str()).c_str(),
		                 E_FILE_NOT_FOUND);
	}

	pi.stat(repository + "/" + caName);

	if(pi.exists())
	{
		LOGIT_ERROR(pi.toString() << " still exist");
		CA_MGM_THROW_ERR(ca_mgm::SystemException,
		                 str::form(__("%s still exists."), pi.toString().c_str()).c_str(),
		                 E_FILE_EXISTS);
	}

	int r = path::createDir(pi.toString(), 0700);

	if( r != 0 )
	{
		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   pi.toString().c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
                     pi.toString().c_str(), ::strerror(r), r).c_str());
	}

	ByteBuffer tmpl;
	try
	{
		tmpl = LocalManagement::readFile(repository + "/openssl.cnf.tmpl");

		std::vector<std::string> tmplArray = PerlRegEx("\n").split(std::string(tmpl.data(), tmpl.size()), true);

		PerlRegEx                   dirR("^\\s*dir\\s*=");
		std::string                      newConf;
		std::vector<std::string>::const_iterator line;

		for(line = tmplArray.begin(); line != tmplArray.end(); ++line)
		{
			if(dirR.match(*line))
			{
				newConf += "dir = " + pi.toString() + "/\n";
			}
			else
			{
				newConf += *line + "\n";
			}
		}

		LocalManagement::writeFile(ByteBuffer(newConf.c_str(), newConf.length()),
		                           pi.toString() + "/openssl.cnf.tmpl");
	}
	catch(Exception &e)
	{
		path::removeDirRecursive(repository + "/" + caName);

		CA_MGM_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Cannot copy the configuration template."), e);
	}

	std::string dir = pi.toString() + "/certs";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   dir.c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
		                    dir.c_str(), ::strerror(r), r).c_str());
	}

	dir = pi.toString() + "/crl";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   dir.c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
		                    dir.c_str(), ::strerror(r), r).c_str());
	}

	dir = pi.toString() + "/newcerts";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   dir.c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
		                    dir.c_str(), ::strerror(r), r).c_str());
	}

	dir = pi.toString() + "/req";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   dir.c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
		                    dir.c_str(), ::strerror(r), r).c_str());
	}

	dir = pi.toString() + "/keys";
	r   = path::createDir(dir, 0700);

	if( r != 0 )
	{
		path::removeDirRecursive(repository + "/" + caName);

		LOGIT_ERROR(str::form("Can not create directory: %s (%s [%d])",
		                   dir.c_str(), ::strerror(r), r));
		CA_MGM_THROW(ca_mgm::SystemException,
		             str::form(__("Cannot create directory: %s (%s [%d])."),
		                    dir.c_str(), ::strerror(r), r).c_str());
	}

	try
	{
		LocalManagement::writeFile(ByteBuffer("01"),
		                           pi.toString() + "/serial");
		LocalManagement::writeFile(ByteBuffer(),
		                           pi.toString() + "/index.txt");
		LocalManagement::writeFile(ByteBuffer(),
		                           pi.toString() + "/cam.txt");
	}
	catch(Exception &e)
	{
		path::removeDirRecursive(repository + "/" + caName);

		CA_MGM_THROW_SUBEX(ca_mgm::SystemException,
		                   __("Cannot create the file."), e);
	}
}

std::string
OpenSSLUtils::digestMD5(const std::string &in)
{
  std::string dcmd;
  bool foundError = false;

  std::string input(::tempnam("/tmp/", "md5in"));
  std::ofstream of(input.c_str());
  if (!of.good())
  {
    ERR << "Can not open file for write" << std::endl;
    CA_MGM_THROW_ERRNO_MSG(ca_mgm::RuntimeException, __("Can not open file."));
  }
  of << in;
  of.close();

  dcmd += ca_mgm::OPENSSL_COMMAND + " ";
  dcmd += "dgst ";
  dcmd += "-md5 ";
  dcmd += input;

  std::vector<std::string> cmd = PerlRegEx("\\s").split(dcmd);

  LOGIT_DEBUG("Command: " << dcmd);

  std::string randfile(::tempnam("/tmp/", ".rand-"));
  Environment env;
  env["PATH"] = "/usr/bin/";
  env["RANDFILE"] = randfile.c_str();

  std::string stdOutput;
  std::string errOutput;
  int         status    = -1;

  try
  {
    status = wrapExecuteProcessAndGatherOutput(cmd, stdOutput,
                                               errOutput, env);
  }
  catch(Exception& e)
  {
    LOGIT_ERROR( "openssl exception:" << e);
    path::removeFile(randfile);
    path::removeFile(input);
    CA_MGM_THROW_SUBEX(ca_mgm::RuntimeException,
                       __("Executing openssl command failed."), e);
  }
  if(status != 0)
  {
    LOGIT_INFO( "openssl status:" << str::numstring(status));
    foundError = true;
  }
  if(!errOutput.empty())
  {
    LOGIT_ERROR("openssl stderr:" << errOutput);
    foundError = true;
  }
  if(!stdOutput.empty())
  {
    LOGIT_DEBUG("openssl stdout:" << stdOutput);

    std::vector<std::string> words;
    str::split( stdOutput, std::back_inserter(words), "=" );
    stdOutput = str::trim(words.back());
    LOGIT_DEBUG("openssl md5sum:" << stdOutput);
  }
  path::removeFile(randfile);
  path::removeFile(input);

  if(foundError)
  {
    CA_MGM_THROW(ca_mgm::RuntimeException,
                 str::form(__("openssl command failed: %s"), errOutput.c_str()).c_str());
  }
  return stdOutput;
}

}
