/*---------------------------------------------------------------------\
|                          ____ _   __ __ ___                          |
|                         |__  / \ / / . \ . \                         |
|                           / / \ V /|  _/  _/                         |
|                          / /__ | | | | | |                           |
|                         /_____||_| |_| |_|                           |
|                                                                      |
\---------------------------------------------------------------------*/
/** \file zypp/ExternalProgram.h
*/


#ifndef CA_MGM_EXTERNALPROGRAM_H
#define CA_MGM_EXTERNALPROGRAM_H

#include <map>
#include <string>
#include <vector>

#include <limal/ExternalDataSource.hpp>
#include <limal/PathName.hpp>

namespace ca_mgm {

    /**
     * @short Execute a program and give access to its io
     * An object of this class encapsulates the execution of
     * an external program. It starts the program using fork
     * and some exec.. call, gives you access to the program's
     * stdio and closes the program after use.
     *
     * \code
     *
     * const char* argv[] =
     * {
     *     "/usr/bin/foo,
     *     "--option1",
     *     "--option2",
     *     NULL
     * };
     *
     * ExternalProgram prog( argv,
     *                        ExternalProgram::Discard_Stderr,
     *                        false, -1, true);
     * string line;
     * for(line = prog.receiveLine();
     *     ! line.empty();
     *     line = prog.receiveLine() )
     * {
     *     stream << line;
     * }
     * prog.close();
     *
     * \endcode
     */
    class ExternalProgram : public ExternalDataSource
    {

    public:

      typedef std::vector<std::string> Arguments;

      /**
       * Define symbols for different policies on the handling
       * of stderr
       */
      enum Stderr_Disposition {
    	Normal_Stderr,
    	Discard_Stderr,
    	Stderr_To_Stdout,
    	Stderr_To_FileDesc
      };


      /**
       * For passing additional environment variables to set
       */
      typedef std::map<std::string,std::string> Environment;

      /**
       * Start the external program by using the shell <tt>/bin/sh<tt>
       * with the option <tt>-c</tt>. You can use io direction symbols < and >.
       * @param commandline a shell commandline that is appended to
       * <tt>/bin/sh -c</tt>.
       * @param default_locale whether to set LC_ALL=C before starting
       * @param root directory to chroot into, / or empty to not chroot
       */
      ExternalProgram (std::string commandline,
    		     Stderr_Disposition stderr_disp = Normal_Stderr,
    		     bool use_pty = false, int stderr_fd = -1, bool default_locale = false,
    		     const path::PathName& root = "");

      /**
       * Start an external program by giving the arguments as an arry of char *pointers.
       * If environment is provided, varaiables will be added to the childs environment,
       * overwriting existing ones.
       * \throws ExternalProgramException if fork fails.
       */

      ExternalProgram();

      ExternalProgram (const Arguments &argv,
    		     Stderr_Disposition stderr_disp = Normal_Stderr,
    		     bool use_pty = false, int stderr_fd = -1, bool default_locale = false,
    		     const path::PathName& root = "");

      ExternalProgram (const Arguments &argv, const Environment & environment,
    		     Stderr_Disposition stderr_disp = Normal_Stderr,
    		     bool use_pty = false, int stderr_fd = -1, bool default_locale = false,
    		     const path::PathName& root = "");

      ExternalProgram (const char *const *argv,
    		     Stderr_Disposition stderr_disp = Normal_Stderr,
    		     bool use_pty = false, int stderr_fd = -1, bool default_locale = false,
    		     const path::PathName& root = "");

      ExternalProgram (const char *const *argv, const Environment & environment,
    		     Stderr_Disposition stderr_disp = Normal_Stderr,
    		     bool use_pty = false, int stderr_fd = -1, bool default_locale = false,
    		     const path::PathName& root = "");

      ExternalProgram (const char *binpath, const char *const *argv_1,
    		     bool use_pty = false);


      ExternalProgram (const char *binpath, const char *const *argv_1, const Environment & environment,
    		     bool use_pty = false);


      ~ExternalProgram();

      int close();

      /**
       * Kill the program
       */
      bool kill();

      /**
       * Return whether program is running
       */
      bool running();

      /**
       * return pid
       * */
      pid_t getpid() { return pid; }

      /** The command we're executing. */
      const std::string & command() const
      { return _command; }

      /** Some detail telling why the execution failed, if it failed.
       * Empty if the command is still running or successfully completed.
       *
       * \li <tt>Can't open pty (%s).</tt>
       * \li <tt>Can't open pipe (%s).</tt>
       * \li <tt>Can't fork (%s).</tt>
       * \li <tt>Command exited with status %d.</tt>
       * \li <tt>Command was killed by signal %d (%s).</tt>
      */
      const std::string & execError() const
      { return _execError; }

      /**
       * origfd will be accessible as newfd and closed (unless they were equal)
       */
      static void renumber_fd (int origfd, int newfd);

    protected:
      int checkStatus( int );

    private:

      /**
       * Set to true, if a pair of ttys is used for communication
       * instead of a pair of pipes.
       */
      bool use_pty;

      pid_t pid;
      int _exitStatus;
      /** Store the command we're executing. */
      std::string _command;
      /** Remember execution errors like failed fork/exec. */
      std::string _execError;

      void start_program (const char *const *argv, const Environment & environment,
    			Stderr_Disposition stderr_disp = Normal_Stderr,
    			int stderr_fd = -1, bool default_locale = false,
    			const char* root = NULL);

    };

} // namespace ca_mgm

#endif // CA_MGM_EXTERNALPROGRAM_H
