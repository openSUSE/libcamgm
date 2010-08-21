%module CaMgm

/*
  for limal libraries use %import _not_ %include
  %include happens in limal (core) library
*/

%{
#include <inttypes.h>
%}

%apply long {time_t};
%apply unsigned long { size_t };

/* Input typemaps */

%typemap(in) int32_t  "$1 = ($1_ltype) SvIV($input);";
%typemap(in) uint32_t "$1 = ($1_ltype) SvUV($input);";

/* Const primitive references.  Passed by value */

%typemap(in) const int32_t &(int32_t temp)
        "temp = ($*1_ltype) SvIV($input);
        $1 = &temp;";

%typemap(in) const uint32_t &(uint32_t temp)
        "temp = ($*1_ltype) SvUV($input);
         $1 = &temp;";

/* Typemap for output values */
%typemap(out) const int32_t, int32_t
    "ST(argvi) = sv_newmortal();
     sv_setiv(ST(argvi++), (IV) $1);";

%typemap(out) const uint32_t, uint32_t
    "ST(argvi) = sv_newmortal();
     sv_setuv(ST(argvi++), (UV) $1);";

/* References to primitive types.  Return by value */

%typemap(out) const int32_t&, int32_t&
      "ST(argvi) = sv_newmortal();
       sv_setiv(ST(argvi++), (IV) *($1));";

%typemap(out) const uint32_t&, uint32_t&
      "ST(argvi) = sv_newmortal();
       sv_setuv(ST(argvi++), (UV) *($1));";


/* Variable input */

%typemap(varin) int32_t  "$1 = ($1_ltype) SvIV($input);";
%typemap(varin) uint32_t "$1 = ($1_ltype) SvUV($input);";

/* Const primitive references.  Passed by value */

%typemap(varin) const int32_t& (int32_t temp)
        "temp = ($*1_ltype) SvIV($input);
         $1 = &temp;";

%typemap(varin) const uint32_t& (uint32_t temp)
        "temp = ($*1_ltype) SvUV($input);
         $1 = &temp;";

/* --- Typemaps for variable output --- */

%typemap(varout) int32_t  "sv_setiv($result, (IV) $1);";
%typemap(varout) uint32_t "sv_setuv($result, (UV) $1);";

%typecheck(SWIG_TYPECHECK_INTEGER)
         int32_t, uint32_t
{
  $1 = SvIOK($input) ? 1 : 0;
}

%include <std_string.i>

%typemap(argout) std::string*, std::string&
{
    if(SvROK($input)) {
        SV *sv = (SV *)SvRV($input);
        sv_setpv(sv, $1->c_str());
    }
}

%typemap(out) std::string {
    if (argvi >= items) EXTEND(sp, 1);  // bump stack ptr, if needed
    char *data = const_cast<char*>($1.c_str());
    sv_setpvn($result = sv_newmortal(), data, $1.length());
    ++argvi;
}

%typemap(out) const std::string &, std::string & {
    if (argvi >= items) EXTEND(sp, 1);  // bump stack ptr, if needed
    char *data = const_cast<char*>($1->c_str());
    sv_setpvn($result = sv_newmortal(), data, $1->length());
    ++argvi;
}


