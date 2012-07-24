/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file src/ExternalProgram.cc
*/

#define _GNU_SOURCE 1 // for ::getline

#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pty.h> // openpty
#include <stdlib.h> // setenv

#include <cstring> // strsignal
#include <iostream>
#include <sstream>

#include <ca-mgm/Logger.hpp>
#include <ca-mgm/String.hpp>
#include <ca-mgm/ExternalProgram.hpp>

#include "Utils.hpp"

using namespace std;
using namespace ca_mgm::path;

namespace ca_mgm {

    ExternalProgram::ExternalProgram()
    : use_pty (false)
    {
    }


    ExternalProgram::ExternalProgram( std::string commandline,
                                      Stderr_Disposition stderr_disp,
                                      bool use_pty,
                                      int stderr_fd,
                                      bool default_locale,
                                      const PathName & root )
    : use_pty (use_pty)
    {
      const char *argv[4];
      argv[0] = "/bin/sh";
      argv[1] = "-c";
      argv[2] = commandline.c_str();
      argv[3] = 0;

      const char* rootdir = NULL;
      if(!root.empty() && root != "/")
      {
    	rootdir = root.asString().c_str();
      }
      Environment environment;
      start_program (argv, environment, stderr_disp, stderr_fd, default_locale, rootdir);
    }


    ExternalProgram::ExternalProgram (const Arguments &argv,
                                      Stderr_Disposition stderr_disp,
                                      bool use_pty, int stderr_fd,
                                      bool default_locale,
                                      const PathName& root)
        : use_pty (use_pty)
    {
        const char * argvp[argv.size() + 1];
        unsigned c = 0;
        for_( i, argv.begin(), argv.end() )
        {
            argvp[c] = i->c_str();
            ++c;
        }
        argvp[c] = 0;

        Environment environment;
        const char* rootdir = NULL;
        if(!root.empty() && root != "/")
        {
            rootdir = root.asString().c_str();
        }
        start_program (argvp, environment, stderr_disp, stderr_fd, default_locale, rootdir);
    }


    ExternalProgram::ExternalProgram (const Arguments &argv,
                                      const Environment & environment,
                                      Stderr_Disposition stderr_disp,
                                      bool use_pty, int stderr_fd,
                                      bool default_locale,
                                      const PathName& root)
        : use_pty (use_pty)
    {
        const char * argvp[argv.size() + 1];
        unsigned c = 0;
        for_( i, argv.begin(), argv.end() )
        {
            argvp[c] = i->c_str();
            ++c;
        }
        argvp[c] = 0;

        const char* rootdir = NULL;
        if(!root.empty() && root != "/")
        {
            rootdir = root.asString().c_str();
        }
        start_program (argvp, environment, stderr_disp, stderr_fd, default_locale, rootdir);

    }




    ExternalProgram::ExternalProgram( const char *const *argv,
                                      Stderr_Disposition stderr_disp,
                                      bool use_pty,
                                      int stderr_fd,
                                      bool default_locale,
                                      const PathName & root )
    : use_pty (use_pty)
    {
      const char* rootdir = NULL;
      if(!root.empty() && root != "/")
      {
    	rootdir = root.asString().c_str();
      }
      Environment environment;
      start_program (argv, environment, stderr_disp, stderr_fd, default_locale, rootdir);
    }


    ExternalProgram::ExternalProgram (const char *const *argv, const Environment & environment,
    				  Stderr_Disposition stderr_disp, bool use_pty,
    				  int stderr_fd, bool default_locale,
    				  const PathName& root)
      : use_pty (use_pty)
    {
      const char* rootdir = NULL;
      if(!root.empty() && root != "/")
      {
    	rootdir = root.asString().c_str();
      }
      start_program (argv, environment, stderr_disp, stderr_fd, default_locale, rootdir);
    }


    ExternalProgram::ExternalProgram (const char *binpath, const char *const *argv_1,
    				  bool use_pty)
      : use_pty (use_pty)
    {
      int i = 0;
      while (argv_1[i++])
    	;
      const char *argv[i + 1];
      argv[0] = binpath;
      memcpy (&argv[1], argv_1, (i - 1) * sizeof (char *));
      Environment environment;
      start_program (argv, environment);
    }


    ExternalProgram::ExternalProgram (const char *binpath, const char *const *argv_1, const Environment & environment,
    				  bool use_pty)
      : use_pty (use_pty)
    {
      int i = 0;
      while (argv_1[i++])
    	;
      const char *argv[i + 1];
      argv[0] = binpath;
      memcpy (&argv[1], argv_1, (i - 1) * sizeof (char *));
      start_program (argv, environment);
    }


    ExternalProgram::~ExternalProgram()
    {
    }


    void
    ExternalProgram::start_program (const char *const *argv, const Environment & environment,
    				Stderr_Disposition stderr_disp,
    				int stderr_fd, bool default_locale, const char* root)
    {
      pid = -1;
      _exitStatus = 0;
      int to_external[2], from_external[2];  // fds for pair of pipes
      int master_tty,	slave_tty;	   // fds for pair of ttys

      // do not remove the single quotes around every argument, copy&paste of
      // command to shell will not work otherwise!
      {
        stringstream cmdstr;
        for (int i = 0; argv[i]; i++)
        {
          if (i>0) cmdstr << ' ';
          cmdstr << '\'';
          cmdstr << argv[i];
          cmdstr << '\'';
        }
        _command = cmdstr.str();
      }
      //DBG << "Executing " << _command << endl;


      if (use_pty)
      {
    	// Create pair of ttys
        DBG << "Using ttys for communication with " << argv[0] << endl;
    	if (openpty (&master_tty, &slave_tty, 0, 0, 0) != 0)
    	{
          _execError = str::form( __("Can't open pty (%s)."), strerror(errno) );
          _exitStatus = 126;
          ERR << _execError << endl;
          return;
    	}
      }
      else
      {
    	// Create pair of pipes
    	if (pipe (to_external) != 0 || pipe (from_external) != 0)
    	{
          _execError = str::form( __("Can't open pipe (%s)."), strerror(errno) );
          _exitStatus = 126;
          ERR << _execError << endl;
          return;
    	}
      }

      // Create module process
      if ((pid = fork()) == 0)
      {
    	if (use_pty)
    	{
    	    setsid();
    	    if(slave_tty != 1)
    		dup2 (slave_tty, 1);	  // set new stdout
    	    renumber_fd (slave_tty, 0);	  // set new stdin
    	    ::close(master_tty);	  // Belongs to father process

    	    // We currently have no controlling terminal (due to setsid).
    	    // The first open call will also set the new ctty (due to historical
    	    // unix guru knowledge ;-) )

    	    char name[512];
    	    ttyname_r(slave_tty, name, sizeof(name));
    	    ::close(open(name, O_RDONLY));
    	}
    	else
    	{
    	    renumber_fd (to_external[0], 0); // set new stdin
    	    ::close(from_external[0]);	  // Belongs to father process

    	    renumber_fd (from_external[1], 1); // set new stdout
    	    ::close(to_external	 [1]);	  // Belongs to father process
    	}

    	// Handle stderr
    	if (stderr_disp == Discard_Stderr)
    	{
    	    int null_fd = open("/dev/null", O_WRONLY);
    	    dup2(null_fd, 2);
    	    ::close(null_fd);
    	}
    	else if (stderr_disp == Stderr_To_Stdout)
    	{
    	    dup2(1, 2);
    	}
    	else if (stderr_disp == Stderr_To_FileDesc)
    	{
    	    // Note: We don't have to close anything regarding stderr_fd.
    	    // Our caller is responsible for that.
    	    dup2 (stderr_fd, 2);
    	}

    	for ( Environment::const_iterator it = environment.begin(); it != environment.end(); ++it ) {
    	  setenv( it->first.c_str(), it->second.c_str(), 1 );
    	}

    	if(default_locale)
    		setenv("LC_ALL","C",1);

    	if(root)
    	{
    	    if(chroot(root) == -1)
    	    {
                _execError = str::form( __("Can't chroot to '%s' (%s)."), root, strerror(errno) );
                ERR << _execError << endl;
                std::cerr << _execError << endl;// After fork log on stderr too
    		_exit (128);			// No sense in returning! I am forked away!!
    	    }
    	    if(chdir("/") == -1)
    	    {
                _execError = str::form( __("Can't chdir to '/' inside chroot (%s)."), strerror(errno) );
                ERR << _execError << endl;
                std::cerr << _execError << endl;// After fork log on stderr too
    		_exit (128);			// No sense in returning! I am forked away!!
    	    }
    	}

    	// close all filedesctiptors above stderr
    	for ( int i = ::getdtablesize() - 1; i > 2; --i ) {
    	  ::close( i );
    	}

    	execvp(argv[0], const_cast<char *const *>(argv));
        // don't want to get here
        _execError = str::form( __("Can't exec '%s' (%s)."), argv[0], strerror(errno) );
        ERR << _execError << endl;
        std::cerr << _execError << endl;// After fork log on stderr too
        _exit (129);			// No sense in returning! I am forked away!!
      }

      else if (pid == -1)	 // Fork failed, close everything.
      {
        _execError = str::form( __("Can't fork (%s)."), strerror(errno) );
        _exitStatus = 127;
        ERR << _execError << endl;

   	if (use_pty) {
    	    ::close(master_tty);
    	    ::close(slave_tty);
    	}
    	else {
    	    ::close(to_external[0]);
    	    ::close(to_external[1]);
    	    ::close(from_external[0]);
    	    ::close(from_external[1]);
    	}
      }

      else {
    	if (use_pty)
    	{
    	    ::close(slave_tty);	       // belongs to child process
    	    inputfile  = fdopen(master_tty, "r");
    	    outputfile = fdopen(master_tty, "w");
    	}
    	else
    	{
    	    ::close(to_external[0]);   // belongs to child process
    	    ::close(from_external[1]); // belongs to child process
    	    inputfile = fdopen(from_external[0], "r");
    	    outputfile = fdopen(to_external[1], "w");
    	}

    	//DBG << "pid " << pid << " launched" << endl;

    	if (!inputfile || !outputfile)
    	{
    	    ERR << "Cannot create streams to external program " << argv[0] << endl;
    	    close();
    	}
      }
    }


    int
    ExternalProgram::close()
    {
      if (pid > 0)
      {
    	ExternalDataSource::close();
    	// Wait for child to exit
    	int ret;
          int status = 0;
    	do
    	{
    	    ret = waitpid(pid, &status, 0);
    	}
    	while (ret == -1 && errno == EINTR);

    	if (ret != -1)
    	{
    	    status = checkStatus( status );
    	}
          pid = -1;
          return status;
      }
      else
      {
          return _exitStatus;
      }
    }


    int ExternalProgram::checkStatus( int status )
    {
      if (WIFEXITED (status))
      {
    	status = WEXITSTATUS (status);
    	if(status)
    	{
    	    DBG << "Pid " << pid << " exited with status " << status << endl;
            _execError = str::form( __("Command exited with status %d."), status );
    	}
    	else
    	{
    	    // if 'launch' is logged, completion should be logged,
    	    // even if successfull.
    	    //DBG << "Pid " << pid << " successfully completed" << endl;
            //_execError = __("Command successfully completed.");
    	}
      }
      else if (WIFSIGNALED (status))
      {
    	status = WTERMSIG (status);
    	WAR << "Pid " << pid << " was killed by signal " << status
    		<< " (" << strsignal(status);
    	if (WCOREDUMP (status))
    	{
    	    WAR << ", core dumped";
    	}
    	WAR << ")" << endl;
        _execError = str::form( __("Command was killed by signal %d (%s)."), status, strsignal(status) );
    	status+=128;
      }
      else {
    	ERR << "Pid " << pid << " exited with unknown error" << endl;
        _execError = __("Command exited with unknown error.");
      }

      return status;
    }

    bool
    ExternalProgram::kill()
    {
      if (pid > 0)
      {
    	::kill(pid, SIGKILL);
    	close();
      }
      return true;
    }


    bool
    ExternalProgram::running()
    {
      if ( pid < 0 ) return false;

      int status = 0;
      int p = waitpid( pid, &status, WNOHANG );
      switch ( p )
        {
        case -1:
          ERR << "waitpid( " << pid << ") returned error '" << strerror(errno) << "'" << endl;
          return false;
          break;
        case 0:
          return true; // still running
          break;
        }

      // Here: completed...
      _exitStatus = checkStatus( status );
      pid = -1;
      return false;
    }

    // origfd will be accessible as newfd and closed (unless they were equal)
    void ExternalProgram::renumber_fd (int origfd, int newfd)
    {
      // It may happen that origfd is already the one we want
      // (Although in our circumstances, that would mean somebody has closed
      // our stdin or stdout... weird but has appened to Cray, #49797)
      if (origfd != newfd)
      {
    	dup2 (origfd, newfd);
    	::close (origfd);
      }
    }

} // namespace ca_mgm
